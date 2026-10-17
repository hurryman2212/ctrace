// Export conservative, instruction-backed C statements to ctrace.
// @category Ctrace

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.ref.SoftReference;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class CtraceDecompileServer extends GhidraScript {
  private static final int MAX_INSTRUCTIONS = 64;
  private static final int MAX_DEPENDENCIES = 4096;
  private static final int DECOMPILE_SECONDS = 30;
  private static final int MAX_REQUEST = 16384;
  private static final int MAX_TYPES = 512;
  private static final int MAX_MEMBERS = 1024;
  private static final int MAX_TYPE_DEPTH = 64;
  private static final int RECENT_ANALYSES = 4;
  private static final int SOFT_ANALYSES = 64;
  private static final int MAX_IMAGE_RECORDS = 65536;
  private final Gson gson = new Gson();
  private final Map<Address, String> failedFunctions = new HashMap<>();
  private final Map<Address, SoftReference<DecompileResults>> analyzedFunctions =
      new LinkedHashMap<>(16, 0.75f, true);
  private final Map<Address, DecompileResults> recentAnalyses =
      new LinkedHashMap<>(16, 0.75f, true);
  private final Map<Long, JsonObject> parameterDescriptions = new HashMap<>();
  private final Map<Long, String> syntheticNames = new HashMap<>();
  private final Set<String> reservedNames = new HashSet<>();
  private final Map<DataType, Integer> typeIds = new IdentityHashMap<>();
  private JsonArray typeRecords = new JsonArray();
  private int memberCount;
  private long linkBase;
  private final JsonArray kernelReturns = new JsonArray();

  private void kernelReturnFlows() throws Exception {
    // Only the kernel preparation copy has these reserved section anchors.
    // A kernel's return mitigation is a tail JMP, not a source function call.
    // Change analysis flow metadata only; exported instruction bytes remain
    // exactly the relocated ELF bytes and the parent validates every override.
    boolean anchored = false;
    for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
      if (symbol.getName().startsWith("__ctrace_analysis_section_")) {
        anchored = true;
        break;
      }
    }
    if (!anchored
        || currentProgram.getDefaultPointerSize() != 8
        || currentProgram.getLanguage().isBigEndian()
        || !currentProgram.getLanguage().getProcessor().toString().equals("x86")) {
      return;
    }
    int transaction = currentProgram.startTransaction("Kernel return thunk flow");
    boolean committed = false;
    try {
      var relocations = currentProgram.getRelocationTable().getRelocations();
      while (relocations.hasNext()) {
        monitor.checkCancelled();
        Relocation relocation = relocations.next();
        if (!"__x86_return_thunk".equals(relocation.getSymbolName())
            || relocation.getStatus() != Relocation.Status.APPLIED
            || (relocation.getType() != 2 && relocation.getType() != 4)) {
          continue;
        }
        Address field = relocation.getAddress();
        Instruction instruction = currentProgram.getListing().getInstructionAt(field.subtract(1));
        if (instruction == null || instruction.getLength() != 5) {
          continue;
        }
        byte[] bytes = instruction.getBytes();
        if ((bytes[0] & 0xff) != 0xe9) {
          continue;
        }
        int displacement =
            (bytes[1] & 0xff)
                | ((bytes[2] & 0xff) << 8)
                | ((bytes[3] & 0xff) << 16)
                | ((bytes[4] & 0xff) << 24);
        Address destination = instruction.getAddress().add(5L + displacement);
        Function stub = currentProgram.getFunctionManager().getFunctionAt(destination);
        Function target = stub == null ? null : stub.getThunkedFunction(true);
        MemoryBlock block = currentProgram.getMemory().getBlock(destination);
        if (block == null
            || !block.isExternalBlock()
            || target == null
            || !target.isExternal()
            || target.getSymbol().getSource() != SourceType.IMPORTED
            || !target.getName().equals("__x86_return_thunk")) {
          continue;
        }
        if (kernelReturns.size() >= MAX_IMAGE_RECORDS) {
          throw new IllegalArgumentException("kernel return flow inventory exceeds its bound");
        }
        instruction.setFlowOverride(FlowOverride.RETURN);
        JsonObject record = new JsonObject();
        record.addProperty(
            "address", "0x" + Long.toUnsignedString(instruction.getAddress().getOffset(), 16));
        record.addProperty("space", instruction.getAddress().getAddressSpace().getName());
        kernelReturns.add(record);
      }
      committed = true;
    } finally {
      currentProgram.endTransaction(transaction, committed);
    }
  }

  private String elfAddress(Address address) {
    return "0x"
        + Long.toUnsignedString(
            address.getOffset() - currentProgram.getImageBase().getOffset() + linkBase, 16);
  }

  private JsonObject failure(String message) {
    JsonObject result = new JsonObject();
    result.addProperty("version", 1);
    result.addProperty("ok", false);
    result.addProperty("error", message);
    return result;
  }

  private void statements(ClangNode node, List<ClangStatement> result) {
    if (node instanceof ClangStatement) {
      result.add((ClangStatement) node);
    }
    for (int index = 0; index < node.numChildren(); ++index) {
      statements(node.Child(index), result);
    }
  }

  private String typeName(DataType declared) {
    Set<DataType> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    String normalized = typeName(declared, "", seen, 0);
    return normalized == null ? declared.getDisplayName() : normalized;
  }

  private String typeName(DataType declared, String suffix, Set<DataType> seen, int depth) {
    if (declared == null || depth >= MAX_TYPE_DEPTH || !seen.add(declared)) {
      return null;
    }
    DataType type = declared;
    while (type instanceof TypeDef) {
      type = ((TypeDef) type).getBaseDataType();
      if (type == null || ++depth >= MAX_TYPE_DEPTH || !seen.add(type)) {
        return null;
      }
    }
    if (type instanceof Pointer) {
      DataType pointed = ((Pointer) type).getDataType();
      return typeName(pointed, "*" + suffix, seen, depth + 1);
    }
    if (type instanceof Array) {
      Array array = (Array) type;
      if (array.getNumElements() < 0) {
        return null;
      }
      // Parenthesize pointer declarators before an array suffix. Arrays of
      // pointers and pointers to arrays must retain different C spellings.
      String declarator = suffix.startsWith("*") ? "(" + suffix + ")" : suffix;
      return typeName(
          array.getDataType(), declarator + "[" + array.getNumElements() + "]", seen, depth + 1);
    }
    int size = type.getLength();
    if ((size == 1 || size == 2 || size == 4 || size == 8)
        && ((type instanceof AbstractIntegerDataType
                && type.getClass() != CharDataType.class
                && !(type instanceof BooleanDataType))
            || (Undefined.isUndefined(type) && !Undefined.isUndefinedArray(type)))) {
      // Width and signedness come from the analyzed target's type, not
      // the host platform or a narrower register slice carrying it.
      boolean signed =
          type instanceof AbstractIntegerDataType && ((AbstractIntegerDataType) type).isSigned();
      String spelling = (signed ? "int" : "uint") + (size * 8) + "_t";
      if (spelling.equals(declared.getDisplayName())) {
        return null;
      }
      return spelling + (suffix.startsWith("*") || suffix.startsWith("(") ? " " : "") + suffix;
    }
    return null;
  }

  private int typeRecord(DataType declared, int depth) {
    if (declared == null || depth >= MAX_TYPE_DEPTH) {
      return 0;
    }
    Integer existing = typeIds.get(declared);
    if (existing != null) {
      return existing;
    }
    if (typeRecords.size() >= MAX_TYPES) {
      return 0;
    }
    DataType type = declared;
    Set<DataType> aliases = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    while (type instanceof TypeDef) {
      if (!aliases.add(type)) {
        return 0;
      }
      type = ((TypeDef) type).getBaseDataType();
    }
    if (type == null || type.getLength() <= 0) {
      return 0;
    }
    int id = typeRecords.size() + 1;
    typeIds.put(declared, id);
    JsonObject record = new JsonObject();
    // Publish the ID before following members/pointees: recursive types
    // refer back to this node instead of duplicating an unbounded tree.
    typeRecords.add(record);
    record.addProperty("kind", "unknown");
    record.addProperty("size", type.getLength());
    record.addProperty("complete", true);
    String scalar = "unknown";
    if (type.isNotYetDefined()) {
      // Ghidra may reserve one byte for a forward declaration. That
      // placeholder is not proof of a known, empty aggregate layout.
      record.addProperty("value_kind", scalar);
      return id;
    }
    if (type instanceof Pointer) {
      record.addProperty("kind", "pointer");
      record.addProperty("element_type", typeRecord(((Pointer) type).getDataType(), depth + 1));
      scalar = "pointer";
    } else if (type instanceof Structure) {
      record.addProperty("kind", "struct");
      JsonArray members = new JsonArray();
      for (DataTypeComponent component : ((Structure) type).getDefinedComponents()) {
        if (memberCount >= MAX_MEMBERS) {
          record.addProperty("complete", false);
          break;
        }
        ++memberCount;
        JsonObject member = new JsonObject();
        String name = component.getFieldName();
        if (name == null || name.isEmpty()) {
          name = component.getDefaultFieldName();
        }
        member.addProperty("name", name);
        member.addProperty("offset", component.getOffset());
        int child = typeRecord(component.getDataType(), depth + 1);
        member.addProperty("type", child);
        member.addProperty(
            "available",
            child != 0
                && !component.isBitFieldComponent()
                && component.getOffset() >= 0
                && component.getLength() > 0
                && component.getDataType().getLength() <= component.getLength()
                && component.getOffset() <= type.getLength() - component.getLength());
        members.add(member);
      }
      record.add("members", members);
    } else if (type instanceof Array) {
      Array array = (Array) type;
      record.addProperty("kind", "array");
      int child = typeRecord(array.getDataType(), depth + 1);
      record.addProperty("element_type", child);
      record.addProperty("element_count", array.getNumElements());
      record.addProperty("element_stride", array.getElementLength());
      record.addProperty(
          "complete",
          child != 0
              && array.getNumElements() > 0
              && array.getElementLength() > 0
              && (long) array.getNumElements() * array.getElementLength() <= type.getLength());
    } else {
      if (type instanceof BooleanDataType) {
        scalar = "boolean";
      } else if (type instanceof AbstractIntegerDataType) {
        scalar = ((AbstractIntegerDataType) type).isSigned() ? "signed" : "unsigned";
      } else if (type instanceof Enum) {
        scalar = ((Enum) type).isSigned() ? "signed" : "unsigned";
      } else if (type instanceof AbstractFloatDataType) {
        scalar = "float";
      }
      if (!scalar.equals("unknown")
          || (Undefined.isUndefined(type) && !Undefined.isUndefinedArray(type))) {
        record.addProperty("kind", "scalar");
      }
    }
    record.addProperty("value_kind", scalar);
    return id;
  }

  private String statementText(ClangStatement statement) {
    List<ClangNode> nodes = new ArrayList<>();
    statement.flatten(nodes);
    return tokensText(nodes);
  }

  private String tokensText(List<ClangNode> nodes) {
    StringBuilder text = new StringBuilder();
    for (ClangNode node : nodes) {
      if (!(node instanceof ClangToken)) {
        continue;
      }
      ClangToken token = (ClangToken) node;
      String part = token.getText();
      if (part == null) {
        part = " ";
      }
      // Clang type tokens exclude pointer/array qualifiers. Replacing
      // only these tokens leaves variable names and string literals
      // containing words such as "uint" untouched.
      if (token instanceof ClangTypeToken) {
        DataType type = ((ClangTypeToken) token).getDataType();
        if (type != null) {
          part = typeName(type);
        }
      }
      // Use the function symbol's provenance, rather than matching arbitrary
      // C text: a literal or user function called FUN_* must remain intact.
      if (token instanceof ClangFuncNameToken) {
        PcodeOp call = token.getPcodeOp();
        if (call != null && call.getOpcode() == PcodeOp.CALL) {
          Address target = call.getInput(0).getAddress();
          Function function = currentProgram.getFunctionManager().getFunctionAt(target);
          if (function != null && function.getSymbol().getSource() == SourceType.DEFAULT) {
            part = "@L" + elfAddress(target).substring(2) + "@";
          }
        }
      }
      HighVariable variable = token.isVariableRef() ? token.getHighVariable() : null;
      HighSymbol symbol = variable == null ? null : variable.getSymbol();
      JsonObject parameter = symbol == null ? null : parameterDescriptions.get(symbol.getId());
      if (parameter != null && !(token instanceof ClangTypeToken)) {
        part = parameter.get("name").getAsString();
      }
      String synthetic = symbol == null ? null : syntheticNames.get(symbol.getId());
      if (synthetic != null && !(token instanceof ClangTypeToken)) {
        part = synthetic;
      }
      if (text.length() != 0
          && !part.isEmpty()
          && Character.isJavaIdentifierPart(text.charAt(text.length() - 1))
          && Character.isJavaIdentifierPart(part.charAt(0))) {
        text.append(' ');
      }
      text.append(part);
    }
    return text.toString().trim();
  }

  private boolean dependencies(
      PcodeOp operation,
      PcodeOp root,
      Set<PcodeOp> roots,
      Set<Varnode> inputs,
      Set<PcodeOp> visited,
      TreeSet<Address> addresses,
      Function function) {
    if (operation == null || (operation != root && roots.contains(operation))) {
      return true;
    }
    if (!visited.add(operation)) {
      return true;
    }
    if (visited.size() > MAX_DEPENDENCIES) {
      return false;
    }
    int opcode = operation.getOpcode();
    // Phi nodes cross executed paths; analysis-only INDIRECT nodes describe
    // call clobbers. Neither has an instruction sequence we can safely fold.
    if (opcode == PcodeOp.MULTIEQUAL || opcode == PcodeOp.INDIRECT) {
      return true;
    }
    Address address = operation.getSeqnum().getTarget();
    if (!function.getBody().contains(address)) {
      return false;
    }
    addresses.add(address);
    for (int index = 0; index < operation.getNumInputs(); ++index) {
      Varnode input = operation.getInput(index);
      if (!inputs.contains(input)
          && !dependencies(input.getDef(), root, roots, inputs, visited, addresses, function)) {
        return false;
      }
    }
    return true;
  }

  private static class Location {
    final boolean stack;
    final long offset;

    Location(boolean stack, long offset) {
      this.stack = stack;
      this.offset = offset;
    }
  }

  private Location location(
      Varnode node,
      Instruction instruction,
      CallDepthChangeInfo depths,
      Map<Varnode, Location> temporaries) {
    if (node.isConstant()) {
      return new Location(false, node.getOffset());
    }
    if (temporaries.containsKey(node)) {
      return temporaries.get(node);
    }
    if (node.isRegister()) {
      Register register = currentProgram.getRegister(node.getAddress(), node.getSize());
      if (register != null) {
        int depth = depths.getRegDepth(instruction.getAddress(), register);
        if (depth != Function.UNKNOWN_STACK_DEPTH_CHANGE
            && depth != Function.INVALID_STACK_DEPTH_CHANGE) {
          return new Location(true, depth);
        }
      }
    }
    return null;
  }

  private void updateLocation(
      PcodeOp operation,
      Instruction instruction,
      CallDepthChangeInfo depths,
      Map<Varnode, Location> temporaries) {
    Varnode output = operation.getOutput();
    if (output == null) {
      return;
    }
    Location value = null;
    int opcode = operation.getOpcode();
    if (opcode == PcodeOp.COPY) {
      value = location(operation.getInput(0), instruction, depths, temporaries);
    } else if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) {
      Location left = location(operation.getInput(0), instruction, depths, temporaries);
      Location right = location(operation.getInput(1), instruction, depths, temporaries);
      if (left != null
          && right != null
          && !(left.stack && right.stack)
          && !(opcode == PcodeOp.INT_SUB && right.stack)) {
        value =
            new Location(
                left.stack || right.stack,
                opcode == PcodeOp.INT_ADD
                    ? left.offset + right.offset
                    : left.offset - right.offset);
      }
    }
    // A null entry also invalidates a formerly known register value within
    // this instruction; never fall back to its pre-instruction stack depth.
    temporaries.put(output, value);
  }

  private boolean stores(
      Instruction instruction, Varnode destination, Varnode source, CallDepthChangeInfo depths) {
    Map<Varnode, Location> temporaries = new HashMap<>();
    Set<Varnode> values = new HashSet<>();
    if (source != null) {
      values.add(new Varnode(source.getAddress(), source.getSize()));
    }
    boolean found = false;
    for (PcodeOp operation : instruction.getPcode()) {
      if (operation.getOpcode() == PcodeOp.STORE) {
        Location pointer = location(operation.getInput(1), instruction, depths, temporaries);
        Varnode input = operation.getInput(2);
        if (pointer != null
            && pointer.stack == destination.getAddress().isStackAddress()
            && pointer.offset == destination.getOffset()
            && input.getSize() == destination.getSize()
            && (source == null || values.contains(input))) {
          found = true;
        } else if (source != null) {
          return false;
        }
      }
      Varnode output = operation.getOutput();
      boolean copied =
          operation.getOpcode() == PcodeOp.COPY && values.contains(operation.getInput(0));
      if (source != null && output != null && output.isRegister()) {
        // Extension may move only the value being committed; an
        // unrelated architectural write would disappear from the trace.
        if (!copied) {
          return false;
        }
      }
      if (output != null) {
        values.remove(output);
        if (copied) {
          values.add(output);
        }
      }
      updateLocation(operation, instruction, depths, temporaries);
    }
    return found;
  }

  private boolean completeAssignment(
      PcodeOp root,
      Set<PcodeOp> roots,
      TreeSet<Address> addresses,
      Function function,
      CallDepthChangeInfo depths) {
    Varnode output = root.getOutput();
    HighVariable high = output == null ? null : output.getHigh();
    HighSymbol symbol = high == null ? null : high.getSymbol();
    if (symbol == null) {
      return true;
    }
    Varnode[] storage = symbol.getStorage().getVarnodes();
    if (storage.length != 1) {
      return false;
    }
    Varnode destination = storage[0];
    if (!destination.getAddress().isStackAddress() && !destination.isAddress()) {
      return true;
    }
    Instruction destinationInstruction =
        currentProgram.getListing().getInstructionAt(root.getSeqnum().getTarget());
    if (destinationInstruction != null
        && stores(destinationInstruction, destination, null, depths)) {
      return true;
    }
    // High p-code may merge a LOAD/LEA into a later stack COPY, retaining
    // only the producer's PC. Commit the printed destination only after the
    // real store. An unproved commit remains assembly, never an early C '='.
    if (!addresses.last().equals(root.getSeqnum().getTarget())) {
      return false;
    }
    Instruction producer = currentProgram.getListing().getInstructionAt(addresses.last());
    if (producer == null || producer.getFallThrough() == null) {
      return false;
    }
    Varnode produced = output.isRegister() ? output : null;
    if (produced == null) {
      // Stack promotion can put the stack address on the high-pcode
      // output itself. Recover its one physical value destination from
      // the decoded producer, not from an assumed ABI register.
      for (PcodeOp operation : producer.getPcode()) {
        Varnode candidate = operation.getOutput();
        if (candidate == null
            || !candidate.isRegister()
            || candidate.getSize() != destination.getSize()) {
          continue;
        }
        if (produced != null && !produced.equals(candidate)) {
          return false;
        }
        produced = candidate;
      }
    }
    if (produced == null) {
      return false;
    }
    Instruction commit = currentProgram.getListing().getInstructionAt(producer.getFallThrough());
    if (commit == null
        || !function.getBody().contains(commit.getMaxAddress())
        || commit.getFlowType().isJump()
        || commit.getFlowType().isCall()
        || commit.getFlowType().isTerminal()) {
      return false;
    }
    for (PcodeOp other : roots) {
      if (other != root && other.getSeqnum().getTarget().equals(commit.getAddress())) {
        return false;
      }
    }
    if (!stores(commit, destination, produced, depths)) {
      return false;
    }
    addresses.add(commit.getAddress());
    return true;
  }

  private JsonObject instructionRecord(Instruction instruction) throws Exception {
    JsonObject encoded = new JsonObject();
    encoded.addProperty("address", elfAddress(instruction.getAddress()));
    StringBuilder bytes = new StringBuilder();
    for (byte value : instruction.getBytes()) {
      bytes.append(String.format("%02x", value & 255));
    }
    encoded.addProperty("bytes", bytes.toString());
    return encoded;
  }

  private JsonObject variableRecord(HighSymbol symbol, Varnode storage) {
    if (storage.getSize() <= 0 || symbol.getName() == null || symbol.getName().isEmpty()) {
      return null;
    }
    JsonObject result = new JsonObject();
    result.addProperty("id", "0x" + Long.toUnsignedString(symbol.getId(), 16));
    result.addProperty("name", syntheticNames.getOrDefault(symbol.getId(), symbol.getName()));
    result.addProperty("type", typeName(symbol.getDataType()));
    result.addProperty("size", storage.getSize());
    // A register-sized piece of an aggregate is not evidence that the
    // entire object resides there. Full stack/global storage is exported
    // separately by variables().
    result.addProperty(
        "type_id",
        symbol.getDataType().getLength() == storage.getSize()
            ? typeRecord(symbol.getDataType(), 0)
            : 0);
    result.addProperty("access", "readwrite");
    DataType type = symbol.getDataType();
    while (type instanceof TypeDef) {
      type = ((TypeDef) type).getBaseDataType();
    }
    String kind = "unknown";
    if (type instanceof Pointer) {
      kind = "pointer";
    } else if (type instanceof BooleanDataType) {
      kind = "boolean";
    } else if (type instanceof AbstractIntegerDataType) {
      kind = ((AbstractIntegerDataType) type).isSigned() ? "signed" : "unsigned";
    } else if (type instanceof Enum) {
      kind = ((Enum) type).isSigned() ? "signed" : "unsigned";
    } else if (type instanceof AbstractFloatDataType) {
      kind = "float";
    }
    result.addProperty("value_kind", kind);
    JsonObject parameter = parameterDescriptions.get(symbol.getId());
    if (parameter != null) {
      result.add("name", parameter.get("name"));
      result.add("type", parameter.get("type"));
      result.add("value_kind", parameter.get("value_kind"));
    }
    if (storage.getAddress().isStackAddress()) {
      result.addProperty("kind", "stack");
      result.addProperty("offset", storage.getOffset());
    } else if (storage.isRegister()) {
      Register register = currentProgram.getRegister(storage.getAddress(), storage.getSize());
      if (register == null) {
        return null;
      }
      result.addProperty("kind", "register");
      result.addProperty("register", register.getName());
    } else if (storage.isAddress()) {
      result.addProperty("kind", "global");
      result.addProperty("offset", elfAddress(storage.getAddress()));
    } else {
      return null;
    }
    return result;
  }

  private JsonArray parameterRecords(HighFunction high, Function function, JsonObject result) {
    parameterDescriptions.clear();
    syntheticNames.clear();
    reservedNames.clear();
    boolean declared =
        function.getSignatureSource() == SourceType.IMPORTED
            || function.getSignatureSource() == SourceType.USER_DEFINED;
    Set<Long> generatedSymbols = new HashSet<>();
    for (int index = 0; index < high.getFunctionPrototype().getNumParams(); ++index) {
      HighSymbol symbol = high.getFunctionPrototype().getParam(index);
      if (!declared
          && !symbol.isNameLocked()
          && (symbol.getSymbol() == null
              || (symbol.getSymbol().getSource() != SourceType.IMPORTED
                  && symbol.getSymbol().getSource() != SourceType.USER_DEFINED))) {
        generatedSymbols.add(symbol.getId());
      }
    }
    List<HighSymbol> symbols = new ArrayList<>();
    high.getLocalSymbolMap().getSymbols().forEachRemaining(symbols::add);
    high.getGlobalSymbolMap().getSymbols().forEachRemaining(symbols::add);
    Set<String> parameterNames = new HashSet<>();
    for (HighSymbol symbol : symbols) {
      if (symbol.getName() != null && !symbol.getName().isEmpty()) {
        reservedNames.add(symbol.getName());
        if (!generatedSymbols.contains(symbol.getId())) {
          parameterNames.add(symbol.getName());
        }
      }
    }
    Set<JsonObject> generated = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    JsonArray parameters = new JsonArray();
    boolean variadic = high.getFunctionPrototype().isVarArg();
    boolean valid = true;
    Set<String> occupied = new HashSet<>();
    for (int index = 0; index < high.getFunctionPrototype().getNumParams(); ++index) {
      HighSymbol symbol = high.getFunctionPrototype().getParam(index);
      Varnode[] storage = symbol.getStorage().getVarnodes();
      JsonObject item = storage.length == 1 ? variableRecord(symbol, storage[0]) : null;
      DataType type = symbol.getDataType();
      while (type instanceof TypeDef) {
        type = ((TypeDef) type).getBaseDataType();
      }
      if (item == null
          || symbol.isHiddenReturn()
          || symbol.getStorage().isForcedIndirect()
          || (!item.get("kind").getAsString().equals("register")
              && !item.get("kind").getAsString().equals("stack"))
          || (storage[0].getSize() != 1
              && storage[0].getSize() != 2
              && storage[0].getSize() != 4
              && storage[0].getSize() != 8)
          || (item.get("value_kind").getAsString().equals("unknown")
              && !Undefined.isUndefined(type))) {
        valid = false;
        break;
      }
      String registerName = null;
      if (storage[0].isRegister()) {
        Register register =
            currentProgram.getRegister(storage[0].getAddress(), storage[0].getSize());
        registerName = register.getName().toLowerCase(java.util.Locale.ROOT);
        String base = register.getBaseRegister().getName();
        if (type instanceof AbstractFloatDataType
            && base.matches("[XYZ]MM[0-7]")
            && storage[0].getAddress().equals(register.getBaseRegister().getAddress())) {
          registerName = "xmm" + base.substring(3);
        }
        occupied.add(register.getBaseRegister().getName());
        item.addProperty("register", registerName);
      }
      if (generatedSymbols.contains(symbol.getId())) {
        generated.add(item);
      } else {
        parameterNames.add(item.get("name").getAsString());
      }
      if (Undefined.isUndefined(type)) {
        item.addProperty("type", "uint" + (storage[0].getSize() * 8) + "_t");
        // uintN_t documents storage width, not a recovered unsigned C
        // type. Keep the value untyped so entry and body use hex.
        item.addProperty("value_kind", "unknown");
      }
      parameters.add(item);
      parameterDescriptions.put(symbol.getId(), item);
    }
    // Optimized-away parameters can survive only as ABI register spills.
    // Inspect reads of incoming SysV integer registers before any write in
    // the entry block; prologue saves of RBX/RBP are not argument evidence.
    // A trusted/variadic prototype already specifies its fixed arguments.
    String[] argumentRegisters = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    if (valid
        && !declared
        && !variadic
        && currentProgram.getDefaultPointerSize() == 8
        && currentProgram.getLanguage().getProcessor().toString().equals("x86")) {
      Map<String, Register> incoming = new HashMap<>();
      Set<String> defined = new HashSet<>();
      Set<String> arguments = new HashSet<>(java.util.Arrays.asList(argumentRegisters));
      Instruction instruction =
          currentProgram.getListing().getInstructionAt(function.getEntryPoint());
      for (int count = 0; instruction != null && count < MAX_INSTRUCTIONS; ++count) {
        if (!function.getBody().contains(instruction.getAddress())
            || instruction.getFlowType().isJump()
            || instruction.getFlowType().isCall()
            || instruction.getFlowType().isTerminal()) {
          break;
        }
        String mnemonic = instruction.getMnemonicString();
        Register left = instruction.getNumOperands() > 0 ? instruction.getRegister(0) : null;
        Register right = instruction.getNumOperands() > 1 ? instruction.getRegister(1) : null;
        boolean zeroIdiom =
            (mnemonic.equalsIgnoreCase("XOR") || mnemonic.equalsIgnoreCase("SUB"))
                && left != null
                && left.equals(right);
        for (PcodeOp operation : instruction.getPcode()) {
          if (!zeroIdiom) {
            for (Varnode input : operation.getInputs()) {
              if (!input.isRegister()) {
                continue;
              }
              Register register = currentProgram.getRegister(input.getAddress(), input.getSize());
              if (register == null
                  || !register.getAddress().equals(register.getBaseRegister().getAddress())) {
                continue;
              }
              String base = register.getBaseRegister().getName();
              if (arguments.contains(base)
                  && !occupied.contains(base)
                  && !defined.contains(base)
                  && (!incoming.containsKey(base)
                      || incoming.get(base).getNumBytes() < register.getNumBytes())) {
                incoming.put(base, register);
              }
            }
          }
          Varnode output = operation.getOutput();
          if (output != null && output.isRegister()) {
            Register register = currentProgram.getRegister(output.getAddress(), output.getSize());
            if (register != null) {
              defined.add(register.getBaseRegister().getName());
            }
          }
        }
        Address next = instruction.getFallThrough();
        instruction = next == null ? null : currentProgram.getListing().getInstructionAt(next);
      }
      for (String base : argumentRegisters) {
        Register register = incoming.get(base);
        if (register == null) {
          continue;
        }
        JsonObject item = new JsonObject();
        String name = register.getName().toLowerCase(java.util.Locale.ROOT);
        item.addProperty("name", name);
        item.addProperty("type", "uint" + (register.getNumBytes() * 8) + "_t");
        item.addProperty("value_kind", "unknown");
        item.addProperty("size", register.getNumBytes());
        item.addProperty("kind", "register");
        item.addProperty("register", name);
        parameters.add(item);
        generated.add(item);
      }
      if (!incoming.isEmpty()) {
        // Fixed integer register positions remain in ABI order when
        // spill evidence supplies an earlier, otherwise unused input.
        List<JsonObject> ordered = new ArrayList<>();
        parameters.forEach(item -> ordered.add(item.getAsJsonObject()));
        boolean integersOnly =
            ordered.stream()
                .allMatch(
                    item ->
                        item.get("kind").getAsString().equals("register")
                            && arguments.contains(
                                currentProgram
                                    .getRegister(item.get("register").getAsString())
                                    .getBaseRegister()
                                    .getName()));
        if (integersOnly) {
          List<String> order = java.util.Arrays.asList(argumentRegisters);
          ordered.sort(
              java.util.Comparator.comparingInt(
                  item ->
                      order.indexOf(
                          currentProgram
                              .getRegister(item.get("register").getAsString())
                              .getBaseRegister()
                              .getName())));
          parameters = new JsonArray();
          ordered.forEach(parameters::add);
        }
      }
    }
    if (!valid) {
      parameters = new JsonArray();
      parameterDescriptions.clear();
    } else {
      // Assign ordinal labels only after spill evidence has restored ABI
      // ordering. The same JsonObjects back parameterDescriptions, so
      // body references and storage metadata receive these final names.
      for (int index = 0; index < parameters.size(); ++index) {
        JsonObject item = parameters.get(index).getAsJsonObject();
        if (generated.contains(item)) {
          int ordinal = index + 1;
          String name = "param_" + ordinal;
          while (parameterNames.contains(name)) {
            name = "param_" + ++ordinal;
          }
          item.addProperty("name", name);
        }
        String name = item.get("name").getAsString();
        parameterNames.add(name);
        reservedNames.add(name);
      }
    }
    result.addProperty("parameters_known", valid && (declared || !parameters.isEmpty()));
    result.addProperty("variadic", variadic);
    return parameters;
  }

  private void syntheticLocalNames(HighFunction high) {
    List<HighSymbol> symbols = new ArrayList<>();
    high.getLocalSymbolMap().getSymbols().forEachRemaining(symbols::add);
    high.getGlobalSymbolMap().getSymbols().forEachRemaining(symbols::add);
    symbols.sort(
        java.util.Comparator.comparing(
                (HighSymbol symbol) -> symbol.getName() == null ? "" : symbol.getName())
            .thenComparingLong(HighSymbol::getId));
    int ordinal = 1;
    for (HighSymbol symbol : symbols) {
      String original = symbol.getName();
      if (original == null
          || (!original.startsWith("in_") && !original.startsWith("unaff_"))
          || symbol.isNameLocked()
          || parameterDescriptions.containsKey(symbol.getId())
          || syntheticNames.containsKey(symbol.getId())
          || (symbol.getSymbol() != null
              && (symbol.getSymbol().getSource() == SourceType.IMPORTED
                  || symbol.getSymbol().getSource() == SourceType.USER_DEFINED))) {
        continue;
      }
      String name;
      do {
        name = "local_" + ordinal++;
      } while (reservedNames.contains(name));
      // A high variable names a value, not whichever value currently
      // occupies its original register. Keep this label and its exact
      // type across copies and overwrites. Runtime bindings still come
      // only from the existing per-PC physical-access/lifetime proof.
      // Segment-base and other unbound inputs may have a C label without
      // a readable runtime location; never invent a register binding.
      syntheticNames.put(symbol.getId(), name);
      reservedNames.add(name);
    }
  }

  private boolean physicalRegister(Instruction instruction, Varnode storage, boolean write) {
    if (instruction == null) {
      return false;
    }
    for (PcodeOp operation : instruction.getPcode()) {
      if (write
          && operation.getOutput() != null
          && storage.getAddress().equals(operation.getOutput().getAddress())
          && storage.getSize() == operation.getOutput().getSize()) {
        return true;
      }
      if (!write) {
        for (Varnode input : operation.getInputs()) {
          if (storage.getAddress().equals(input.getAddress())
              && storage.getSize() == input.getSize()) {
            return true;
          }
        }
        // Later pcode operations may read a temporary register value just
        // written by this same instruction (for example x86 zero extension).
        // Those reads do not prove the register held this variable beforehand.
        if (operation.getOutput() != null && storage.intersects(operation.getOutput())) {
          return false;
        }
      }
    }
    return false;
  }

  private static class Spill {
    final HighSymbol symbol;
    final Varnode storage;
    final Address instruction;

    Spill(HighSymbol symbol, Varnode storage, Address instruction) {
      this.symbol = symbol;
      this.storage = storage;
      this.instruction = instruction;
    }
  }

  private void parameterSpills(
      List<HighSymbol> symbols, Function function, CallDepthChangeInfo depths, JsonArray result) {
    Map<Varnode, HighSymbol> origins = new HashMap<>();
    for (HighSymbol symbol : symbols) {
      Varnode[] storage = symbol.getStorage().getVarnodes();
      if (symbol.isParameter() && storage.length == 1 && storage[0].isRegister()) {
        origins.put(new Varnode(storage[0].getAddress(), storage[0].getSize()), symbol);
      }
    }
    if (origins.isEmpty()) {
      return;
    }
    List<Spill> spills = new ArrayList<>();
    Instruction instruction =
        currentProgram.getListing().getInstructionAt(function.getEntryPoint());
    for (int count = 0; instruction != null && count < MAX_INSTRUCTIONS; ++count) {
      if (!function.getBody().contains(instruction.getAddress())
          || instruction.getFlowType().isJump()
          || instruction.getFlowType().isCall()
          || instruction.getFlowType().isTerminal()) {
        break;
      }
      origins.keySet().removeIf(Varnode::isUnique);
      Map<Varnode, Location> temporaries = new HashMap<>();
      for (PcodeOp operation : instruction.getPcode()) {
        if (operation.getOpcode() == PcodeOp.STORE) {
          Location pointer = location(operation.getInput(1), instruction, depths, temporaries);
          Varnode input = operation.getInput(2);
          HighSymbol symbol = origins.get(input);
          if (pointer != null && pointer.stack && symbol != null) {
            Varnode storage =
                new Varnode(
                    currentProgram.getAddressFactory().getStackSpace().getAddress(pointer.offset),
                    input.getSize());
            spills.add(new Spill(symbol, storage, instruction.getAddress()));
          }
        }
        Varnode output = operation.getOutput();
        if (output != null) {
          HighSymbol origin =
              operation.getOpcode() == PcodeOp.COPY
                      && output.getSize() == operation.getInput(0).getSize()
                  ? origins.get(operation.getInput(0))
                  : null;
          // Partial register writes invalidate the wider argument;
          // equal values alone are never evidence for an alias.
          origins.keySet().removeIf(key -> key.intersects(output));
          if (origin != null) {
            origins.put(output, origin);
          }
        }
        updateLocation(operation, instruction, depths, temporaries);
      }
      Address next = instruction.getFallThrough();
      instruction = next == null ? null : currentProgram.getListing().getInstructionAt(next);
    }
    if (spills.isEmpty()) {
      return;
    }
    // A leaf, fixed stack slot with one proven write retains that exact
    // parameter value. Calls or unknown stores can mutate an escaped slot,
    // and any overlapping write ends the proof, even on an untaken path.
    Set<Spill> valid = new HashSet<>(spills);
    for (Instruction item : currentProgram.getListing().getInstructions(function.getBody(), true)) {
      if (item.getFlowType().isCall() || item.getFlowType().isComputed()) {
        return;
      }
      Map<Varnode, Location> temporaries = new HashMap<>();
      for (PcodeOp operation : item.getPcode()) {
        if (operation.getOpcode() == PcodeOp.CALLOTHER) {
          return;
        }
        if (operation.getOpcode() == PcodeOp.STORE) {
          Location pointer = location(operation.getInput(1), item, depths, temporaries);
          if (pointer == null) {
            return;
          }
          if (pointer.stack) {
            Varnode stored =
                new Varnode(
                    currentProgram.getAddressFactory().getStackSpace().getAddress(pointer.offset),
                    operation.getInput(2).getSize());
            valid.removeIf(
                spill ->
                    spill.storage.intersects(stored)
                        && (!spill.instruction.equals(item.getAddress())
                            || !spill.storage.equals(stored)));
          }
        }
        updateLocation(operation, item, depths, temporaries);
      }
    }
    for (Spill spill : valid) {
      boolean unique = true;
      for (HighSymbol other : symbols) {
        for (Varnode storage : other.getStorage().getVarnodes()) {
          if (spill.storage.intersects(storage)) {
            unique = false;
          }
        }
      }
      for (Spill other : spills) {
        if (other != spill && other.storage.intersects(spill.storage)) {
          unique = false;
        }
      }
      JsonObject record = unique ? variableRecord(spill.symbol, spill.storage) : null;
      if (record != null) {
        result.add(record);
      }
    }
  }

  private JsonArray variables(HighFunction high, Function function, CallDepthChangeInfo depths) {
    JsonArray result = new JsonArray();
    List<HighSymbol> symbols = new ArrayList<>();
    high.getLocalSymbolMap().getSymbols().forEachRemaining(symbols::add);
    high.getGlobalSymbolMap().getSymbols().forEachRemaining(symbols::add);
    for (HighSymbol symbol : symbols) {
      Varnode[] storage = symbol.getStorage().getVarnodes();
      if (storage.length != 1) {
        continue;
      }
      if (storage[0].getAddress().isStackAddress() || storage[0].isAddress()) {
        // Reused or partially overlapping storage cannot have a single
        // function-wide name. Keep these accesses unnamed until a
        // precise lifetime is available.
        boolean unique = true;
        for (HighSymbol other : symbols) {
          if (other == symbol) {
            continue;
          }
          for (Varnode candidate : other.getStorage().getVarnodes()) {
            if (storage[0].intersects(candidate)) {
              unique = false;
            }
          }
        }
        JsonObject variable = unique ? variableRecord(symbol, storage[0]) : null;
        if (variable != null) {
          result.add(variable);
        }
      }
      HighVariable variable = symbol.getHighVariable();
      if (variable == null) {
        continue;
      }
      Set<String> seen = new HashSet<>();
      for (Varnode instance : variable.getInstances()) {
        if (!instance.isRegister()) {
          continue;
        }
        PcodeOp definition = instance.getDef();
        if (definition == null && instance.isInput()) {
          JsonObject item = variableRecord(symbol, instance);
          if (item != null) {
            item.addProperty("address", elfAddress(function.getEntryPoint()));
            item.addProperty("access", "read");
            result.add(item);
          }
        }
        List<PcodeOp> accesses = new ArrayList<>();
        if (definition != null) {
          accesses.add(definition);
          if (definition.getOpcode() == PcodeOp.CALL || definition.getOpcode() == PcodeOp.CALLIND) {
            Instruction call =
                currentProgram.getListing().getInstructionAt(definition.getSeqnum().getTarget());
            JsonObject item = variableRecord(symbol, instance);
            if (call != null
                && call.getFallThrough() != null
                && item != null
                && seen.add(call.getFallThrough() + ":" + instance + ":false")) {
              item.addProperty("address", elfAddress(call.getFallThrough()));
              item.addProperty("access", "read");
              result.add(item);
            }
          }
        }
        instance.getDescendants().forEachRemaining(accesses::add);
        for (PcodeOp operation : accesses) {
          Address address = operation.getSeqnum().getTarget();
          boolean write = operation == definition;
          // A register holding a future stack assignment is a value
          // temporary, not that memory lvalue. Name the actual store.
          if (write
              && (!storage[0].isRegister()
                  || !storage[0].getAddress().equals(instance.getAddress())
                  || storage[0].getSize() != instance.getSize())) {
            continue;
          }
          Instruction instruction = currentProgram.getListing().getInstructionAt(address);
          if (!function.getBody().contains(address)
              || !physicalRegister(instruction, instance, write)
              || !seen.add(address + ":" + instance + ":" + write)) {
            continue;
          }
          JsonObject item = variableRecord(symbol, instance);
          if (item != null) {
            item.addProperty("address", elfAddress(address));
            item.addProperty("access", write ? "write" : "read");
            result.add(item);
          }
        }
      }
    }
    parameterSpills(symbols, function, depths, result);
    return result;
  }

  private JsonObject declarationRecord(ClangStatement statement) {
    List<ClangNode> nodes = new ArrayList<>();
    statement.flatten(nodes);
    HighSymbol symbol = null;
    for (ClangNode node : nodes) {
      if (!(node instanceof ClangToken)) {
        continue;
      }
      ClangToken token = (ClangToken) node;
      String part = token.getText();
      if (part == null || part.trim().isEmpty()) {
        continue;
      }
      if (symbol == null) {
        if (!token.isVariableRef() || token instanceof ClangTypeToken) {
          return null;
        }
        HighVariable variable = token.getHighVariable();
        symbol = variable == null ? null : variable.getSymbol();
        if (symbol == null || symbol.getId() == 0) {
          return null;
        }
        continue;
      }
      // A subscript, dereference, compound update, or member assignment
      // cannot become a declaration by inserting a type before it.
      if (!part.trim().equals("=")) {
        return null;
      }
      DataType type = symbol.getDataType();
      while (type instanceof TypeDef) {
        type = ((TypeDef) type).getBaseDataType();
      }
      int size = type.getLength();
      if ((size != 1 && size != 2 && size != 4 && size != 8)
          || (!(type instanceof Pointer)
              && !(type instanceof AbstractIntegerDataType)
              && !(type instanceof AbstractFloatDataType)
              && !(type instanceof BooleanDataType)
              && !(type instanceof Enum)
              && !(Undefined.isUndefined(type) && !Undefined.isUndefinedArray(type)))) {
        return null;
      }
      String spelling = typeName(symbol.getDataType());
      if (!spelling.matches("[A-Za-z_][A-Za-z_0-9 *]*")) {
        return null;
      }
      JsonObject result = new JsonObject();
      result.addProperty("id", "0x" + Long.toUnsignedString(symbol.getId(), 16));
      result.addProperty("name", syntheticNames.getOrDefault(symbol.getId(), symbol.getName()));
      result.addProperty("type", spelling);
      JsonObject parameter = parameterDescriptions.get(symbol.getId());
      if (parameter != null) {
        result.add("name", parameter.get("name"));
        result.add("type", parameter.get("type"));
      }
      return result;
    }
    return null;
  }

  private boolean callPreparation(Instruction instruction) {
    if (instruction == null
        || !instruction.getMnemonicString().equalsIgnoreCase("MOV")
        || instruction.getNumOperands() != 2
        || instruction.getFlowType().isJump()
        || instruction.getFlowType().isCall()
        || instruction.getFlowType().isTerminal()) {
      return false;
    }
    Register destination = instruction.getRegister(0);
    Register source = instruction.getRegister(1);
    if (destination == null
        || (destination.getNumBytes() != 4 && destination.getNumBytes() != 8)
        || !destination.getAddress().equals(destination.getBaseRegister().getAddress())
        || (source == null && instruction.getScalar(1) == null)
        || (source != null
            && !source
                .getBaseRegister()
                .getName()
                .matches("R(AX|BX|CX|DX|SI|DI|BP|SP|[89]|1[0-5])"))) {
      return false;
    }
    String base = destination.getBaseRegister().getName();
    if (base.equals("RAX")) {
      // SysV variadic calls communicate their vector-argument count in
      // AL. Compilers commonly materialize it through a zero-extending
      // EAX move which vanishes from the decompiler's high p-code.
      // Ghidra can expose MOV EAX,imm32 as a full RAX COPY after its
      // architectural zero extension, so both operand spellings apply.
      if ((!destination.getName().equals("EAX") && !destination.getName().equals("RAX"))
          || instruction.getScalar(1) == null
          || Long.compareUnsigned(instruction.getScalar(1).getUnsignedValue(), 8) > 0) {
        return false;
      }
    } else if (!base.matches("R(DI|SI|DX|CX|8|9)")) {
      return false;
    }
    boolean written = false;
    for (PcodeOp operation : instruction.getPcode()) {
      if (operation.getOpcode() != PcodeOp.COPY && operation.getOpcode() != PcodeOp.INT_ZEXT) {
        return false;
      }
      for (Varnode input : operation.getInputs()) {
        if (!input.isRegister() && !input.isConstant() && !input.isUnique()) {
          return false;
        }
      }
      Varnode output = operation.getOutput();
      if (output == null || (!output.isRegister() && !output.isUnique())) {
        return false;
      }
      if (output.isRegister()) {
        Register register = currentProgram.getRegister(output.getAddress(), output.getSize());
        if (register == null || !register.getBaseRegister().getName().equals(base)) {
          return false;
        }
        written = true;
      }
    }
    return written;
  }

  private JsonObject mappedStatement(
      ClangStatement statement, Function function, Set<PcodeOp> roots, CallDepthChangeInfo depths)
      throws Exception {
    PcodeOp root = statement.getPcodeOp();
    if (root == null) {
      return null;
    }
    int opcode = root.getOpcode();
    if (opcode == PcodeOp.RETURN
        && root.getNumInputs() < 2
        && function.getSignatureSource() != SourceType.IMPORTED
        && function.getSignatureSource() != SourceType.USER_DEFINED) {
      // An untyped function analyzed before its callers can be guessed
      // void even when it returns a value. Preserve the observed RET.
      return null;
    }
    // Control structure boundaries are still emitted by the trace's CFG
    // layer. Only whole executable statements may replace instructions.
    if (opcode == PcodeOp.BRANCH
        || opcode == PcodeOp.CBRANCH
        || opcode == PcodeOp.BRANCHIND
        || opcode == PcodeOp.MULTIEQUAL
        || opcode == PcodeOp.INDIRECT
        || opcode == PcodeOp.CALLOTHER) {
      return null;
    }
    TreeSet<Address> addresses = new TreeSet<>();
    Set<Varnode> inputs = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    List<ClangNode> tokens = new ArrayList<>();
    statement.flatten(tokens);
    for (ClangNode node : tokens) {
      if (node instanceof ClangToken) {
        ClangToken token = (ClangToken) node;
        Varnode variable = token.getVarnode();
        // A printed named input refers to a value already available at
        // this statement, not to reevaluation of its earlier producer.
        if (token.isVariableRef()
            && variable != null
            && variable != root.getOutput()
            && variable.getHigh() != null
            && variable.getHigh().getSymbol() != null) {
          inputs.add(variable);
        }
      }
    }
    Set<PcodeOp> visited = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    if (!dependencies(root, root, roots, inputs, visited, addresses, function)
        || addresses.isEmpty()) {
      return null;
    }
    if (!completeAssignment(root, roots, addresses, function, depths)) {
      return null;
    }
    if (opcode == PcodeOp.CALL
        && currentProgram.getDefaultPointerSize() == 8
        && currentProgram.getLanguage().getProcessor().toString().equals("x86")
        && currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().equals("gcc")) {
      Function target =
          currentProgram.getFunctionManager().getFunctionAt(root.getInput(0).getAddress());
      String convention = target == null ? null : target.getCallingConventionName();
      if (convention == null
          || convention.equals("unknown")
          || convention.equals("default")
          || convention.equals("__cdecl")) {
        TreeSet<Address> preparation = new TreeSet<>();
        Address cursor = addresses.first();
        while (cursor.compareTo(addresses.last()) < 0 && preparation.size() < MAX_INSTRUCTIONS) {
          Instruction instruction = currentProgram.getListing().getInstructionAt(cursor);
          if (instruction == null
              || !function.getBody().contains(instruction.getMaxAddress())
              || (!addresses.contains(cursor) && !callPreparation(instruction))) {
            break;
          }
          preparation.add(cursor);
          cursor = instruction.getMaxAddress().add(1);
        }
        // Expand only a complete, bounded call-preparation interval.
        // Any flag write, memory access, unrelated register update,
        // control transfer or independent statement still rejects it.
        if (cursor.equals(addresses.last())) {
          addresses.addAll(preparation);
        }
      }
    }
    // Every machine instruction covered by a statement must be accounted
    // for by its high-pcode dependency graph or proven ABI preparation.
    // Other gaps stay as assembly.
    JsonArray instructions = new JsonArray();
    Address expected = addresses.first();
    for (Address address : addresses) {
      if (!address.equals(expected) || instructions.size() >= MAX_INSTRUCTIONS) {
        return null;
      }
      for (PcodeOp other : roots) {
        if (other != root && other.getSeqnum().getTarget().equals(address)) {
          return null;
        }
      }
      Instruction instruction = currentProgram.getListing().getInstructionAt(address);
      if (instruction == null || !function.getBody().contains(instruction.getMaxAddress())) {
        return null;
      }
      boolean last = address.equals(addresses.last());
      if (instruction.getFlowType().isJump()
          || (!last
              && (instruction.getFlowType().isCall() || instruction.getFlowType().isTerminal()))) {
        return null;
      }
      if (last
          && instruction.getFlowType().isCall()
          && opcode != PcodeOp.CALL
          && opcode != PcodeOp.CALLIND) {
        return null;
      }
      instructions.add(instructionRecord(instruction));
      expected = instruction.getMaxAddress().add(1);
    }
    JsonObject result = new JsonObject();
    String text = statementText(statement);
    if (text.isEmpty()
        || text.length() >= 4095
        || text.indexOf('\n') >= 0
        || text.indexOf('\r') >= 0
        || text.indexOf('\0') >= 0) {
      return null;
    }
    // Clang places the terminating semicolon beside, rather than inside,
    // the statement group. The p-code root above identifies its semantics.
    if (!text.endsWith(";")) {
      text += ";";
    }
    result.addProperty("safe", true);
    result.addProperty("text", text);
    JsonObject declaration = declarationRecord(statement);
    if (declaration != null) {
      result.add("declaration", declaration);
    }
    result.add("instructions", instructions);
    return result;
  }

  private JsonObject returnRecord(HighFunction high, Function function) {
    JsonObject result = new JsonObject();
    result.addProperty("known", false);
    if (high == null || high.getFunctionPrototype().hasNoReturn()) {
      return result;
    }
    if (function.getReturn().isForcedIndirect()) {
      // Ghidra exposes hidden aggregate/oversized return buffers as a
      // pointer in its high prototype. That is not a scalar C return.
      result.addProperty("unsupported", true);
      return result;
    }
    DataType declared = high.getFunctionPrototype().getReturnType();
    DataType type = declared;
    while (type instanceof TypeDef) {
      type = ((TypeDef) type).getBaseDataType();
    }
    if (type instanceof VoidDataType) {
      // An untyped function analyzed before callers may be guessed void.
      if (function.getSignatureSource() == SourceType.IMPORTED
          || function.getSignatureSource() == SourceType.USER_DEFINED) {
        result.addProperty("known", true);
        result.addProperty("void", true);
        result.addProperty("type", "void");
      }
      return result;
    }
    // Concrete type metadata with an unsupported ABI blocks the caller's
    // scalar-width fallback. Missing/inferred undefined types do not.
    result.addProperty("unsupported", !Undefined.isUndefined(type));
    VariableStorage storage = high.getFunctionPrototype().getReturnStorage();
    if (storage == null
        || storage.isForcedIndirect()
        || storage.getVarnodeCount() != 1
        || !storage.getVarnodes()[0].isRegister()) {
      return result;
    }
    Varnode node = storage.getVarnodes()[0];
    int size = type.getLength();
    if ((size != 1 && size != 2 && size != 4 && size != 8) || node.getSize() != size) {
      return result;
    }
    Register register = currentProgram.getRegister(node.getAddress(), node.getSize());
    if (register == null || !node.getAddress().equals(register.getBaseRegister().getAddress())) {
      return result;
    }
    String base = register.getBaseRegister().getName();
    String kind = "unknown";
    if (type instanceof Pointer && size == 8) {
      kind = "pointer";
    } else if (type instanceof BooleanDataType) {
      kind = "boolean";
    } else if (type instanceof AbstractIntegerDataType) {
      kind = ((AbstractIntegerDataType) type).isSigned() ? "signed" : "unsigned";
    } else if (type instanceof Enum) {
      kind = ((Enum) type).isSigned() ? "signed" : "unsigned";
    } else if (type instanceof AbstractFloatDataType && (size == 4 || size == 8)) {
      kind = "float";
    } else if (!Undefined.isUndefined(type)) {
      // Structures and vector values are not scalar return contracts.
      return result;
    }
    boolean floating = kind.equals("float");
    if ((!floating && !base.equalsIgnoreCase("RAX"))
        || (floating
            && !base.equalsIgnoreCase("XMM0")
            && !base.equalsIgnoreCase("YMM0")
            && !base.equalsIgnoreCase("ZMM0"))) {
      return result;
    }
    result.addProperty("known", true);
    result.addProperty("unsupported", false);
    result.addProperty("void", false);
    result.addProperty("type", kind.equals("unknown") ? "?" : typeName(declared));
    result.addProperty("value_kind", kind);
    result.addProperty("size", size);
    result.addProperty(
        "register",
        floating ? "xmm0" : size == 1 ? "al" : size == 2 ? "ax" : size == 4 ? "eax" : "rax");
    return result;
  }

  private JsonObject controlHeader(List<ClangNode> nodes, ClangStatement statement) {
    List<ClangNode> condition = new ArrayList<>();
    statement.flatten(condition);
    if (condition.isEmpty()) {
      return new JsonObject();
    }
    int first = nodes.indexOf(condition.get(0));
    int last = nodes.indexOf(condition.get(condition.size() - 1));
    for (int index = first - 1; index >= 0; --index) {
      if (!(nodes.get(index) instanceof ClangToken)) {
        continue;
      }
      String keyword = ((ClangToken) nodes.get(index)).getText();
      if (!"for".equals(keyword)
          && !"while".equals(keyword)
          && !"if".equals(keyword)
          && !"switch".equals(keyword)) {
        continue;
      }
      int opening = index + 1;
      while (opening < nodes.size()
          && (!(nodes.get(opening) instanceof ClangToken)
              || ((ClangToken) nodes.get(opening)).getText().trim().isEmpty())) {
        ++opening;
      }
      if (opening >= nodes.size() || !"(".equals(((ClangToken) nodes.get(opening)).getText())) {
        continue;
      }
      int depth = 1;
      List<Integer> separators = new ArrayList<>();
      for (int closing = opening + 1; closing < nodes.size(); ++closing) {
        if (!(nodes.get(closing) instanceof ClangToken)) {
          continue;
        }
        String text = ((ClangToken) nodes.get(closing)).getText();
        if ("(".equals(text)) {
          ++depth;
        } else if (")".equals(text)) {
          --depth;
        } else if (";".equals(text) && depth == 1) {
          separators.add(closing);
        }
        if (depth == 0) {
          if (opening < first && last < closing) {
            JsonObject header = new JsonObject();
            header.addProperty("kind", keyword);
            if ("for".equals(keyword) && separators.size() == 2) {
              header.addProperty(
                  "initializer", tokensText(nodes.subList(opening + 1, separators.get(0))));
              header.addProperty(
                  "update", tokensText(nodes.subList(separators.get(1) + 1, closing)));
            }
            return header;
          }
          break;
        }
      }
    }
    return new JsonObject();
  }

  private String controlOperand(Varnode value, Set<Varnode> active, int depth, boolean expand) {
    if (value == null || depth > 32 || !active.add(value)) {
      return null;
    }
    try {
      if (value.isConstant()) {
        return "0x" + Long.toUnsignedString(value.getOffset(), 16);
      }
      HighVariable high = value.getHigh();
      HighSymbol symbol = high == null ? null : high.getSymbol();
      if (!expand && symbol != null && symbol.getName() != null) {
        JsonObject parameter = parameterDescriptions.get(symbol.getId());
        return parameter != null
            ? parameter.get("name").getAsString()
            : syntheticNames.getOrDefault(symbol.getId(), symbol.getName());
      }
      PcodeOp definition = value.getDef();
      if (definition == null) {
        return null;
      }
      int opcode = definition.getOpcode();
      if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.BOOL_NEGATE) {
        String inner =
            controlOperand(
                definition.getInput(0), active, depth + 1, opcode == PcodeOp.BOOL_NEGATE);
        return inner == null ? null : opcode == PcodeOp.BOOL_NEGATE ? "!(" + inner + ")" : inner;
      }
      String operator;
      switch (opcode) {
        case PcodeOp.INT_EQUAL:
          operator = "==";
          break;
        case PcodeOp.INT_NOTEQUAL:
          operator = "!=";
          break;
        case PcodeOp.INT_LESS:
        case PcodeOp.INT_SLESS:
          operator = "<";
          break;
        case PcodeOp.INT_LESSEQUAL:
        case PcodeOp.INT_SLESSEQUAL:
          operator = "<=";
          break;
        case PcodeOp.BOOL_AND:
          operator = "&&";
          break;
        case PcodeOp.BOOL_OR:
          operator = "||";
          break;
        case PcodeOp.BOOL_XOR:
          operator = "!=";
          break;
        case PcodeOp.INT_ADD:
          operator = "+";
          break;
        case PcodeOp.INT_SUB:
          operator = "-";
          break;
        case PcodeOp.INT_AND:
          operator = "&";
          break;
        case PcodeOp.INT_OR:
          operator = "|";
          break;
        case PcodeOp.INT_XOR:
          operator = "^";
          break;
        default:
          return null;
      }
      boolean booleanInputs =
          opcode == PcodeOp.BOOL_AND || opcode == PcodeOp.BOOL_OR || opcode == PcodeOp.BOOL_XOR;
      String left = controlOperand(definition.getInput(0), active, depth + 1, booleanInputs);
      String right = controlOperand(definition.getInput(1), active, depth + 1, booleanInputs);
      if (left == null || right == null) {
        return null;
      }
      if (opcode == PcodeOp.INT_LESS
          || opcode == PcodeOp.INT_LESSEQUAL
          || opcode == PcodeOp.INT_SLESS
          || opcode == PcodeOp.INT_SLESSEQUAL) {
        boolean signed = opcode == PcodeOp.INT_SLESS || opcode == PcodeOp.INT_SLESSEQUAL;
        int bits = definition.getInput(0).getSize() * 8;
        if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
          return null;
        }
        String type = (signed ? "int" : "uint") + bits + "_t";
        left = "(" + type + ")(" + left + ")";
        right = "(" + type + ")(" + right + ")";
      }
      return "(" + left + " " + operator + " " + right + ")";
    } finally {
      active.remove(value);
    }
  }

  private JsonObject imageManifest() throws Exception {
    JsonObject result = new JsonObject();
    result.addProperty("version", 1);
    result.addProperty("ok", true);
    result.addProperty("manifest_version", 1);
    result.addProperty(
        "image_base", "0x" + Long.toUnsignedString(currentProgram.getImageBase().getOffset(), 16));
    result.addProperty(
        "address_space", currentProgram.getAddressFactory().getDefaultAddressSpace().getName());
    result.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
    result.addProperty("big_endian", currentProgram.getLanguage().isBigEndian());
    JsonArray sections = new JsonArray();
    JsonArray imports = new JsonArray();
    String prefix = "__ctrace_analysis_section_";
    for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
      monitor.checkCancelled();
      Address address = symbol.getAddress();
      MemoryBlock block = currentProgram.getMemory().getBlock(address);
      if (symbol.getName().startsWith(prefix)) {
        String indexText = symbol.getName().substring(prefix.length());
        if (!indexText.matches("[1-9][0-9]*")
            || block == null
            || sections.size() >= MAX_IMAGE_RECORDS) {
          return failure("invalid or excessive analysis section anchors");
        }
        long index = Long.parseLong(indexText);
        if (index > 0xffffffffL) {
          return failure("analysis section index exceeds its bound");
        }
        JsonObject entry = new JsonObject();
        entry.addProperty("index", index);
        entry.addProperty("anchor", symbol.getName());
        entry.addProperty("address", "0x" + Long.toUnsignedString(address.getOffset(), 16));
        entry.addProperty("space", address.getAddressSpace().getName());
        entry.addProperty(
            "block_begin", "0x" + Long.toUnsignedString(block.getStart().getOffset(), 16));
        entry.addProperty("block_size", block.getSize());
        entry.addProperty("block_name", block.getName());
        entry.addProperty("block_flags", block.getFlags());
        entry.addProperty("read", block.isRead());
        entry.addProperty("write", block.isWrite());
        entry.addProperty("execute", block.isExecute());
        entry.addProperty("initialized", block.isInitialized());
        entry.addProperty("overlay", block.isOverlay());
        sections.add(entry);
      }
      if (symbol.isExternal() || (block != null && block.isExternalBlock())) {
        if (imports.size() >= MAX_IMAGE_RECORDS) {
          return failure("imported symbol inventory exceeds its bound");
        }
        JsonObject entry = new JsonObject();
        entry.addProperty("name", symbol.getName());
        entry.addProperty("address", "0x" + Long.toUnsignedString(address.getOffset(), 16));
        entry.addProperty("space", address.getAddressSpace().getName());
        entry.addProperty("source", symbol.getSource().toString());
        entry.addProperty("type", symbol.getSymbolType().toString());
        entry.addProperty("external", symbol.isExternal());
        entry.addProperty("namespace", symbol.getParentNamespace().getName(true));
        entry.addProperty("block", block == null ? "" : block.getName());
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        Function thunk = function == null ? null : function.getThunkedFunction(true);
        if (thunk != null) {
          Symbol target = thunk.getSymbol();
          JsonObject reference = new JsonObject();
          reference.addProperty("name", target.getName());
          reference.addProperty(
              "address", "0x" + Long.toUnsignedString(target.getAddress().getOffset(), 16));
          reference.addProperty("space", target.getAddress().getAddressSpace().getName());
          reference.addProperty("source", target.getSource().toString());
          reference.addProperty("external", target.isExternal());
          entry.add("thunk", reference);
        }
        imports.add(entry);
      }
    }
    JsonArray relocations = new JsonArray();
    var iterator = currentProgram.getRelocationTable().getRelocations();
    while (iterator.hasNext()) {
      monitor.checkCancelled();
      if (relocations.size() >= MAX_IMAGE_RECORDS) {
        return failure("relocation inventory exceeds its bound");
      }
      Relocation relocation = iterator.next();
      Address address = relocation.getAddress();
      JsonObject entry = new JsonObject();
      entry.addProperty("address", "0x" + Long.toUnsignedString(address.getOffset(), 16));
      entry.addProperty("space", address.getAddressSpace().getName());
      entry.addProperty("type", relocation.getType());
      entry.addProperty("status", relocation.getStatus().name());
      entry.addProperty("status_code", relocation.getStatus().getValue());
      entry.addProperty(
          "symbol_name", relocation.getSymbolName() == null ? "" : relocation.getSymbolName());
      JsonArray values = new JsonArray();
      if (relocation.getValues() != null) {
        for (long value : relocation.getValues()) {
          values.add("0x" + Long.toUnsignedString(value, 16));
        }
        if (relocation.getValues().length == 1 && relocation.getValues()[0] >= 0) {
          // ELF importer stores the original symbol index. The original
          // anchored relocation identifies its symbol-table section.
          entry.addProperty("symbol_index", relocation.getValues()[0]);
        }
      }
      entry.add("values", values);
      byte[] original = relocation.getBytes();
      if (original == null) original = new byte[0];
      if (original.length > 16) {
        return failure("relocation byte range exceeds its bound");
      }
      byte[] current = new byte[original.length];
      if (current.length != 0
          && currentProgram.getMemory().getBytes(address, current) != current.length) {
        return failure("cannot read complete relocated bytes");
      }
      entry.addProperty("length", original.length);
      entry.addProperty("original_bytes", HexFormat.of().formatHex(original));
      entry.addProperty("current_bytes", HexFormat.of().formatHex(current));
      relocations.add(entry);
    }
    result.add("sections", sections);
    result.add("symbols", imports);
    result.add("relocations", relocations);
    result.add("kernel_returns", kernelReturns);
    return result;
  }

  private JsonObject query(JsonObject request, DecompInterface decompiler, BufferedWriter output)
      throws Exception {
    if (request.has("command") && request.get("command").getAsString().equals("image_manifest")) {
      return imageManifest();
    }
    String level = request.has("level") ? request.get("level").getAsString() : "full";
    if (!level.equals("perfetto") && !level.equals("full")) {
      return failure("decompilation requires perfetto or full instrumentation");
    }
    linkBase = Long.parseUnsignedLong(request.get("link_base").getAsString().substring(2), 16);
    long offset = Long.parseUnsignedLong(request.get("address").getAsString().substring(2), 16);
    Address address = currentProgram.getImageBase().add(offset - linkBase);
    if (!currentProgram.getMemory().contains(address)) {
      return failure("address is outside the imported ELF module");
    }
    Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
    if (function == null) {
      // A stripped binary may expose a function only when the trace calls
      // it. Create it at that observed address; uncertain regions remain ASM.
      disassemble(address);
      function = createFunction(address, null);
      decompiler.flushCache();
      analyzedFunctions.clear();
      recentAnalyses.clear();
    }
    if (function == null || function.isExternal()) {
      return failure("no executable function at the requested address");
    }
    String previousFailure = failedFunctions.get(function.getEntryPoint());
    if (previousFailure != null) {
      return failure(previousFailure);
    }
    SoftReference<DecompileResults> prepared = analyzedFunctions.get(function.getEntryPoint());
    DecompileResults decompiled = prepared == null ? null : prepared.get();
    boolean reused = decompiled != null;
    if (!reused) {
      JsonObject progress = new JsonObject();
      progress.addProperty("stage", "decompile");
      progress.addProperty("detail", "Decompiling " + function.getName());
      progress.addProperty(
          "begin_offset",
          function.getBody().getMinAddress().subtract(currentProgram.getImageBase()));
      progress.addProperty(
          "end_offset",
          function.getBody().getMaxAddress().subtract(currentProgram.getImageBase()) + 1);
      JsonObject notification = new JsonObject();
      notification.add("progress", progress);
      output.write(gson.toJson(notification));
      output.newLine();
      output.flush();
      decompiled = decompiler.decompileFunction(function, DECOMPILE_SECONDS, monitor);
      if (!decompiled.decompileCompleted() || decompiled.getCCodeMarkup() == null) {
        String message =
            "Ghidra could not decompile this function: " + decompiled.getErrorMessage();
        failedFunctions.put(function.getEntryPoint(), message);
        JsonObject error = failure(message);
        error.addProperty("analysis_reused", false);
        return error;
      }
      analyzedFunctions.put(function.getEntryPoint(), new SoftReference<>(decompiled));
      while (analyzedFunctions.size() > SOFT_ANALYSES) {
        analyzedFunctions.remove(analyzedFunctions.keySet().iterator().next());
      }
    }
    // Keep immediate perfetto -> full enrichment warm without pinning every
    // high-function graph ever visited. Older graphs are collectable under
    // heap pressure; published immutable views remain available independently.
    recentAnalyses.put(function.getEntryPoint(), decompiled);
    while (recentAnalyses.size() > RECENT_ANALYSES) {
      recentAnalyses.remove(recentAnalyses.keySet().iterator().next());
    }
    JsonObject result = new JsonObject();
    result.addProperty("level", level);
    result.addProperty("analysis_reused", reused);
    result.addProperty("name", function.getName());
    result.add("parameters", parameterRecords(decompiled.getHighFunction(), function, result));
    typeIds.clear();
    typeRecords = new JsonArray();
    memberCount = 0;
    syntheticLocalNames(decompiled.getHighFunction());
    List<ClangStatement> statements = new ArrayList<>();
    statements(decompiled.getCCodeMarkup(), statements);
    Set<PcodeOp> roots = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    for (ClangStatement statement : statements) {
      if (statement.getPcodeOp() != null) {
        roots.add(statement.getPcodeOp());
      }
    }
    CallDepthChangeInfo depths =
        new CallDepthChangeInfo(function, function.getBody(), null, monitor);
    JsonArray lines = new JsonArray();
    JsonArray controls = new JsonArray();
    List<ClangNode> allTokens = new ArrayList<>();
    decompiled.getCCodeMarkup().flatten(allTokens);
    Map<PcodeOp, ClangStatement> controlStatements = new IdentityHashMap<>();
    for (ClangStatement statement : statements) {
      if (statement.getPcodeOp() != null) {
        controlStatements.put(statement.getPcodeOp(), statement);
      }
    }
    List<PcodeOp> operations = new ArrayList<>();
    decompiled.getHighFunction().getPcodeOps().forEachRemaining(operations::add);
    for (PcodeOp root : operations) {
      if (root != null
          && (root.getOpcode() == PcodeOp.CBRANCH || root.getOpcode() == PcodeOp.BRANCHIND)) {
        Address controlAddress = root.getSeqnum().getTarget();
        Instruction instruction = currentProgram.getListing().getInstructionAt(controlAddress);
        boolean conditional = root.getOpcode() == PcodeOp.CBRANCH;
        // Structured decompilation may negate the condition and swap
        // CFG edges without updating the original CBRANCH address
        // operand. The high block's true/false edges are authoritative.
        PcodeBlockBasic block = root instanceof PcodeOpAST ? ((PcodeOpAST) root).getParent() : null;
        Address target =
            conditional && block != null && block.getOutSize() == 2
                ? block.getTrueOut().getStart()
                : null;
        Address falseTarget =
            conditional && block != null && block.getOutSize() == 2
                ? block.getFalseOut().getStart()
                : null;
        boolean proven =
            instruction != null
                && instruction.getFlowType().isJump()
                && function.getBody().contains(controlAddress);
        if (conditional) {
          Address[] flows = instruction == null ? new Address[0] : instruction.getFlows();
          proven &=
              instruction != null
                  && instruction.getFlowType().isConditional()
                  && target != null
                  && falseTarget != null
                  && flows.length == 1
                  && ((target.equals(flows[0]) && falseTarget.equals(instruction.getFallThrough()))
                      || (falseTarget.equals(flows[0])
                          && target.equals(instruction.getFallThrough())));
        }
        String text =
            proven
                ? controlOperand(
                    root.getInput(conditional ? 1 : 0),
                    java.util.Collections.newSetFromMap(new IdentityHashMap<>()),
                    0,
                    conditional)
                : null;
        if (text != null && !text.isEmpty() && text.length() < 4096) {
          ClangStatement statement = controlStatements.get(root);
          JsonObject control =
              statement == null ? new JsonObject() : controlHeader(allTokens, statement);
          control.add("instruction", instructionRecord(instruction));
          control.addProperty("text", text);
          control.addProperty("conditional", conditional);
          if (conditional) {
            control.addProperty("target", elfAddress(target));
          }
          controls.add(control);
        }
      }
    }
    for (ClangStatement statement : statements) {
      JsonObject line = mappedStatement(statement, function, roots, depths);
      if (line != null) {
        lines.add(line);
      }
    }
    JsonArray ranges = new JsonArray();
    for (AddressRange range : function.getBody().getAddressRanges()) {
      JsonObject item = new JsonObject();
      item.addProperty("start", elfAddress(range.getMinAddress()));
      item.addProperty("end", elfAddress(range.getMaxAddress().add(1)));
      ranges.add(item);
    }
    result.addProperty("version", 1);
    result.addProperty("ok", true);
    result.addProperty("entry", elfAddress(function.getBody().getMinAddress()));
    result.addProperty("end", elfAddress(function.getBody().getMaxAddress().add(1)));
    result.add("ranges", ranges);
    result.add("lines", lines);
    result.add("controls", controls);
    if (level.equals("full")) {
      result.add("variables", variables(decompiled.getHighFunction(), function, depths));
      result.add("types", typeRecords);
    }
    result.add("return", returnRecord(decompiled.getHighFunction(), function));
    JsonArray instructions = new JsonArray();
    for (Instruction instruction :
        currentProgram.getListing().getInstructions(function.getBody(), true)) {
      instructions.add(instructionRecord(instruction));
    }
    result.add("instructions", instructions);
    if (level.equals("full")) {
      // The complete exported record is retained by the worker. Nothing
      // remains to enrich, so the intermediate high-function tree can go.
      analyzedFunctions.remove(function.getEntryPoint());
      recentAnalyses.remove(function.getEntryPoint());
    }
    return result;
  }

  @Override
  protected void run() throws Exception {
    String[] arguments = getScriptArgs();
    if (arguments.length != 1) {
      throw new IllegalArgumentException("expected a private UNIX socket path");
    }
    kernelReturnFlows();
    DecompInterface decompiler = new DecompInterface();
    decompiler.toggleCCode(true);
    decompiler.toggleSyntaxTree(true);
    if (!decompiler.openProgram(currentProgram)) {
      throw new IllegalStateException("cannot initialize Ghidra decompiler");
    }
    try (SocketChannel connection = SocketChannel.open(UnixDomainSocketAddress.of(arguments[0]));
        BufferedReader input =
            new BufferedReader(
                new InputStreamReader(
                    Channels.newInputStream(connection), StandardCharsets.UTF_8));
        BufferedWriter output =
            new BufferedWriter(
                new OutputStreamWriter(
                    Channels.newOutputStream(connection), StandardCharsets.UTF_8))) {
      output.write("{\"ready\":true,\"version\":1}\n");
      output.flush();
      String line;
      while ((line = input.readLine()) != null) {
        JsonObject response;
        try {
          if (line.length() > MAX_REQUEST) {
            throw new IllegalArgumentException("request is too large");
          }
          JsonObject request = JsonParser.parseString(line).getAsJsonObject();
          if (request.has("command") && request.get("command").getAsString().equals("quit")) {
            break;
          }
          response = query(request, decompiler, output);
        } catch (Exception error) {
          response = failure(error.getClass().getSimpleName() + ": " + error.getMessage());
        }
        output.write(gson.toJson(response));
        output.newLine();
        output.flush();
      }
    } finally {
      decompiler.dispose();
    }
  }
}
