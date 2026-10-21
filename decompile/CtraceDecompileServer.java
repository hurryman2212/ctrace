// SPDX-License-Identifier: MIT

// Export conservative, instruction-backed C statements to ctrace.
// @category Ctrace

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
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
import ghidra.program.model.symbol.FlowType;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class CtraceDecompileServer extends GhidraScript {
  private static final int RECENT_ANALYSES = 4;
  private static final int SOFT_ANALYSES = 64;
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
        Instruction instruction = currentProgram.getListing().getInstructionContaining(field);
        if (instruction == null) {
          continue;
        }
        // Ghidra may already classify this tail JMP as CALL_RETURN. Check
        // machine flow before any inferred override, including a cached RETURN.
        FlowType flow = instruction.getPrototype().getFlowType(instruction.getInstructionContext());
        if (!flow.isJump()
            || flow.isConditional()
            || flow.isComputed()
            || instruction.getLength() < 5
            || !instruction.getAddress().add(instruction.getLength() - 4).equals(field)) {
          continue;
        }
        byte[] bytes = instruction.getBytes();
        int operand = bytes.length - 4;
        if ((bytes[operand - 1] & 0xff) != 0xe9) {
          continue;
        }
        int displacement =
            (bytes[operand] & 0xff)
                | ((bytes[operand + 1] & 0xff) << 8)
                | ((bytes[operand + 2] & 0xff) << 16)
                | ((bytes[operand + 3] & 0xff) << 24);
        Address destination = instruction.getAddress().add((long) bytes.length + displacement);
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
    String normalized = typeName(declared, "", seen);
    return normalized == null ? declared.getDisplayName() : normalized;
  }

  private String typeName(DataType declared, String suffix, Set<DataType> seen) {
    if (declared == null || !seen.add(declared)) {
      return null;
    }
    DataType type = declared;
    while (type instanceof TypeDef) {
      type = ((TypeDef) type).getBaseDataType();
      if (type == null || !seen.add(type)) {
        return null;
      }
    }
    if (type instanceof Pointer) {
      DataType pointed = ((Pointer) type).getDataType();
      return typeName(pointed, "*" + suffix, seen);
    }
    if (type instanceof Array) {
      Array array = (Array) type;
      if (array.getNumElements() < 0) {
        return null;
      }
      // Parenthesize pointer declarators before an array suffix. Arrays of
      // pointers and pointers to arrays must retain different C spellings.
      String declarator = suffix.startsWith("*") ? "(" + suffix + ")" : suffix;
      return typeName(array.getDataType(), declarator + "[" + array.getNumElements() + "]", seen);
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

  private int typeRecord(DataType declared) {
    if (declared == null) {
      return 0;
    }
    Integer existing = typeIds.get(declared);
    if (existing != null) {
      return existing;
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
      record.addProperty("element_type", typeRecord(((Pointer) type).getDataType()));
      scalar = "pointer";
    } else if (type instanceof Structure) {
      record.addProperty("kind", "struct");
      JsonArray members = new JsonArray();
      for (DataTypeComponent component : ((Structure) type).getDefinedComponents()) {
        JsonObject member = new JsonObject();
        String name = component.getFieldName();
        if (name == null || name.isEmpty()) {
          name = component.getDefaultFieldName();
        }
        member.addProperty("name", name);
        member.addProperty("offset", component.getOffset());
        int child = typeRecord(component.getDataType());
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
      int child = typeRecord(array.getDataType());
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
    List<PcodeOp> pending = new ArrayList<>();
    if (operation != null) pending.add(operation);
    while (!pending.isEmpty()) {
      PcodeOp current = pending.remove(pending.size() - 1);
      if ((current != root && roots.contains(current)) || !visited.add(current)) continue;
      int opcode = current.getOpcode();
      // Phi nodes cross executed paths; INDIRECT nodes describe call clobbers.
      // Neither has an instruction sequence we can safely fold.
      if (opcode == PcodeOp.MULTIEQUAL || opcode == PcodeOp.INDIRECT) continue;
      Address address = current.getSeqnum().getTarget();
      if (!function.getBody().contains(address)) return false;
      addresses.add(address);
      for (Varnode input : current.getInputs()) {
        PcodeOp definition = input.getDef();
        if (!inputs.contains(input) && definition != null) pending.add(definition);
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
            ? typeRecord(symbol.getDataType())
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
      String name = register.getName();
      String base = register.getBaseRegister().getName();
      if (type instanceof AbstractFloatDataType
          && storage.getAddress().equals(register.getBaseRegister().getAddress())
          && (storage.getSize() == 4 || storage.getSize() == 8)
          && base.matches("[XYZ]MM([0-9]|[12][0-9]|3[01])")) {
        name = "XMM" + base.substring(3);
      }
      result.addProperty("register", name);
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
      while (instruction != null) {
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
    while (instruction != null) {
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
        while (cursor.compareTo(addresses.last()) < 0) {
          Instruction instruction = currentProgram.getListing().getInstructionAt(cursor);
          if (instruction == null
              || !function.getBody().contains(instruction.getMaxAddress())
              || (!addresses.contains(cursor) && !callPreparation(instruction))) {
            break;
          }
          preparation.add(cursor);
          cursor = instruction.getMaxAddress().add(1);
        }
        // Expand only a complete call-preparation interval.
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
      if (!address.equals(expected)) {
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
    if ((size != 1 && size != 2 && size != 4 && size != 8 && size != 10)
        || node.getSize() != size) {
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
    } else if (type instanceof AbstractFloatDataType && (size == 4 || size == 8 || size == 10)) {
      kind = "float";
    } else if (!Undefined.isUndefined(type)) {
      // Structures and vector values are not scalar return contracts.
      return result;
    }
    boolean floating = kind.equals("float");
    boolean x87 = floating && size == 10 && base.equalsIgnoreCase("ST0");
    if ((!floating && !base.equalsIgnoreCase("RAX"))
        || (floating
            && !x87
            && (size == 10
                || (!base.equalsIgnoreCase("XMM0")
                    && !base.equalsIgnoreCase("YMM0")
                    && !base.equalsIgnoreCase("ZMM0"))))) {
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
        floating
            ? (x87 ? "st0" : "xmm0")
            : size == 1 ? "al" : size == 2 ? "ax" : size == 4 ? "eax" : "rax");
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

  private String controlOperand(Varnode value, Set<Varnode> active, boolean expand) {
    if (value == null || !active.add(value)) {
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
            controlOperand(definition.getInput(0), active, opcode == PcodeOp.BOOL_NEGATE);
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
      String left = controlOperand(definition.getInput(0), active, booleanInputs);
      String right = controlOperand(definition.getInput(1), active, booleanInputs);
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
    result.addProperty("ok", true);
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
        if (!indexText.matches("[1-9][0-9]*") || block == null) {
          return failure("invalid analysis section anchors");
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

  // GCC/Clang's LSDA describes protected machine-code ranges, not the original
  // lexical braces. Export only ranges and handlers that the bytes prove.
  private record ExceptionFrame(Address start, Address end, Address lsda) {}

  private record ExceptionCie(int fdeEncoding, int lsdaEncoding, boolean cpp) {}

  private record ExceptionScope(
      String kind,
      String text,
      AddressSet ranges,
      Address entry,
      int selectorRegister,
      int selectorBytes,
      long selectorValue) {}

  private record ExceptionHandler(Address entry, ExceptionState state) {}

  private record ExceptionCandidate(
      ExceptionHandler handler, String text, AddressSet body, AddressSet proof) {}

  private List<ExceptionFrame> exceptionFrames;
  private final Map<Address, List<ExceptionFrame>> exceptionFramesByEntry = new HashMap<>();
  private Map<Address, Set<ExceptionFrame>> exceptionColdSources;
  private final Set<Address> exceptionFunctionAttempts = new HashSet<>();
  private final Map<Address, Function> exceptionOwners = new HashMap<>();
  private final Set<Address> exceptionOwnerAttempts = new HashSet<>();

  private final class ExceptionReader {
    private Address cursor;
    private final Address end;

    ExceptionReader(Address start, Address end) {
      this.cursor = start;
      this.end = end;
    }

    long fixed(int size) throws Exception {
      if (size < 1 || size > 8 || cursor.add(size - 1).compareTo(end) >= 0) {
        throw new IllegalArgumentException("truncated exception record");
      }
      long value = 0;
      for (int i = 0; i < size; ++i) {
        value |= (currentProgram.getMemory().getByte(cursor.add(i)) & 255L) << (i * 8);
      }
      cursor = cursor.add(size);
      return value;
    }

    long leb(boolean signed) throws Exception {
      long value = 0;
      for (int i = 0; i < 10; ++i) {
        long part = fixed(1);
        if (i == 9 && (signed ? (part & 127) != 0 && (part & 127) != 127 : (part & 127) > 1)) {
          throw new IllegalArgumentException("exception integer overflow");
        }
        value |= (part & 127) << (i * 7);
        if ((part & 128) == 0) {
          int bits = (i + 1) * 7;
          if (signed && bits < 64 && (part & 64) != 0) value |= -1L << bits;
          return value;
        }
      }
      throw new IllegalArgumentException("unterminated exception integer");
    }

    long encoded(int encoding, boolean pointer) throws Exception {
      Address position = cursor;
      long value;
      switch (encoding & 15) {
        case 0, 4 -> value = fixed(8);
        case 1 -> value = leb(false);
        case 2 -> value = fixed(2);
        case 3 -> value = fixed(4);
        case 9 -> value = leb(true);
        case 10 -> value = (short) fixed(2);
        case 11 -> value = (int) fixed(4);
        case 12 -> value = fixed(8);
        default -> throw new IllegalArgumentException("unsupported exception encoding");
      }
      if (!pointer) return value;
      // A zero encoded pointer is null before applying relative/indirect flags.
      if (value == 0) return 0;
      switch (encoding & 112) {
        case 0 -> {}
        case 16 -> value = Math.addExact(position.getOffset(), value);
        default -> throw new IllegalArgumentException("unsupported exception pointer base");
      }
      return value;
    }

    ExceptionReader bounded(long size) {
      if (size < 0 || size > end.subtract(cursor)) {
        throw new IllegalArgumentException("exception record exceeds its section");
      }
      Address start = cursor;
      cursor = cursor.add(size);
      return new ExceptionReader(start, cursor);
    }
  }

  private String exceptionSymbol(Address address) {
    if (address == null) return "";
    for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(address)) {
      String name = symbol.getName();
      if (name.startsWith("DW.ref.")) name = name.substring(7);
      if (name.startsWith("_ZTI") || name.equals("__gxx_personality_v0")) return name;
    }
    for (Relocation relocation : currentProgram.getRelocationTable().getRelocations(address)) {
      String name = relocation.getSymbolName();
      if (name != null && (name.startsWith("_ZTI") || name.equals("__gxx_personality_v0"))) {
        return name;
      }
    }
    return "";
  }

  private Address exceptionPointer(long value, int encoding) throws Exception {
    if (value == 0) return null;
    Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    if ((encoding & 128) != 0) {
      value = new ExceptionReader(address, address.add(8)).fixed(8);
      if (value == 0) return null;
      address = address.getAddressSpace().getAddress(value);
    }
    return address;
  }

  private String exceptionType(Address position, long value, int encoding) throws Exception {
    if (value == 0) {
      // An unresolved relocation is an unknown type, not an ABI catch-all.
      for (Relocation ignored : currentProgram.getRelocationTable().getRelocations(position)) {
        return null;
      }
      return "...";
    }
    Address slot = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    Address address = exceptionPointer(value, encoding);
    String name = exceptionSymbol(address);
    if (name.isEmpty() && (encoding & 128) != 0) name = exceptionSymbol(slot);
    if (name.isEmpty() && address != null) {
      // A stripped local type_info still has its ABI name pointer in word 1.
      MemoryBlock block = currentProgram.getMemory().getBlock(address);
      if (block == null || !block.isInitialized() || block.isExecute()) return null;
      long pointer = new ExceptionReader(address.add(8), address.add(16)).fixed(8);
      Address text = address.getAddressSpace().getAddress(pointer);
      StringBuilder encoded = new StringBuilder("_ZTI");
      MemoryBlock names = currentProgram.getMemory().getBlock(text);
      if (names == null || !names.isInitialized() || names.isExecute()) return null;
      for (Address cursor = text; names.contains(cursor); cursor = cursor.add(1)) {
        monitor.checkCancelled();
        int ch = currentProgram.getMemory().getByte(cursor) & 255;
        if (ch == 0) {
          name = encoded.toString();
          break;
        }
        if (ch < 32 || ch >= 127) return null;
        encoded.append((char) ch);
      }
    }
    if (!name.startsWith("_ZTI")) return null;
    int suffix = name.indexOf('@');
    if (suffix >= 0) name = name.substring(0, suffix);
    for (var demangled : DemanglerUtil.demangle(currentProgram, name, address)) {
      String text = demangled.getOriginalDemangled();
      if (text != null && text.startsWith("typeinfo for ")) {
        text = text.substring(13);
        if (!text.isEmpty()
            && text.chars().allMatch(ch -> ch >= 32 && ch < 127 && ch != '{' && ch != '}')) {
          return text;
        }
      }
    }
    return null;
  }

  private List<ExceptionFrame> exceptionFrames() {
    if (exceptionFrames != null) return exceptionFrames;
    exceptionFrames = new ArrayList<>();
    if (currentProgram.getDefaultPointerSize() != 8
        || currentProgram.getLanguage().isBigEndian()
        || !currentProgram.getLanguage().getProcessor().toString().equals("x86")) {
      return exceptionFrames;
    }
    MemoryBlock block = currentProgram.getMemory().getBlock(".eh_frame");
    if (block == null || !block.isInitialized()) {
      return exceptionFrames;
    }
    Map<Address, ExceptionCie> cies = new HashMap<>();
    try {
      ExceptionReader section = new ExceptionReader(block.getStart(), block.getEnd().add(1));
      while (section.cursor.compareTo(section.end) < 0) {
        monitor.checkCancelled();
        Address recordAddress = section.cursor;
        long length = section.fixed(4);
        if (length == 0) break;
        // Extended DWARF64 lengths remain on the ordinary disassembly path.
        if (length == 0xffffffffL) break;
        ExceptionReader record = section.bounded(length);
        Address pointerAddress = record.cursor;
        long cieOffset = record.fixed(4);
        if (cieOffset == 0) {
          int version = (int) record.fixed(1);
          StringBuilder augmentation = new StringBuilder();
          while (true) {
            int ch = (int) record.fixed(1);
            if (ch == 0) break;
            augmentation.append((char) ch);
          }
          if ((version != 1 && version != 3 && version != 4)
              || augmentation.length() == 0
              || augmentation.charAt(0) != 'z') continue;
          if (version == 4 && (record.fixed(1) != 8 || record.fixed(1) != 0)) continue;
          record.leb(false);
          record.leb(true);
          if (version == 1) record.fixed(1);
          else record.leb(false);
          ExceptionReader extra = record.bounded(record.leb(false));
          int fdeEncoding = 0;
          int lsdaEncoding = 255;
          boolean cpp = false;
          boolean valid = true;
          for (int i = 1; i < augmentation.length(); ++i) {
            switch (augmentation.charAt(i)) {
              case 'L' -> lsdaEncoding = (int) extra.fixed(1);
              case 'R' -> fdeEncoding = (int) extra.fixed(1);
              case 'P' -> {
                int encoding = (int) extra.fixed(1);
                long pointer = extra.encoded(encoding, true);
                Address slot =
                    pointer == 0 ? null : pointerAddress.getAddressSpace().getAddress(pointer);
                Address target = exceptionPointer(pointer, encoding);
                cpp =
                    exceptionSymbol(target).equals("__gxx_personality_v0")
                        || ((encoding & 128) != 0
                            && exceptionSymbol(slot).equals("__gxx_personality_v0"));
              }
              case 'S' -> {}
              default -> valid = false;
            }
            if (!valid) break;
          }
          if (valid) cies.put(recordAddress, new ExceptionCie(fdeEncoding, lsdaEncoding, cpp));
        } else {
          if (cieOffset > pointerAddress.subtract(block.getStart())) continue;
          ExceptionCie cie = cies.get(pointerAddress.subtract(cieOffset));
          if (cie == null || !cie.cpp || cie.lsdaEncoding == 255) continue;
          long pc = record.encoded(cie.fdeEncoding, true);
          if ((cie.fdeEncoding & 128) != 0) continue;
          long size = record.encoded(cie.fdeEncoding & 15, false);
          ExceptionReader extra = record.bounded(record.leb(false));
          Address lsda = exceptionPointer(extra.encoded(cie.lsdaEncoding, true), cie.lsdaEncoding);
          if (pc == 0 || size <= 0 || lsda == null) continue;
          Address start = pointerAddress.getAddressSpace().getAddress(pc);
          Address end = start.add(size);
          MemoryBlock code = currentProgram.getMemory().getBlock(start);
          MemoryBlock table = currentProgram.getMemory().getBlock(lsda);
          if (code != null
              && code.isExecute()
              && code.contains(end.subtract(1))
              && table != null
              && table.isInitialized()
              && !table.isExecute()) {
            exceptionFrames.add(new ExceptionFrame(start, end, lsda));
          }
        }
      }
    } catch (Exception error) {
      // A malformed/unsupported unwind table must not fail ordinary tracing.
      exceptionFrames.clear();
    }
    for (ExceptionFrame frame : exceptionFrames)
      exceptionFramesByEntry.computeIfAbsent(frame.start, unused -> new ArrayList<>()).add(frame);
    return exceptionFrames;
  }

  private Function exceptionFunction(Address address, DecompInterface decompiler) {
    for (ExceptionFrame frame : exceptionFrames()) {
      if (address.compareTo(frame.start) < 0 || address.compareTo(frame.end) >= 0) continue;
      Function function = currentProgram.getFunctionManager().getFunctionAt(frame.start);
      if (function == null || function.isExternal()) continue;
      if (!exceptionFunctionAttempts.add(frame.start)) {
        if (function.getBody().contains(address)) return function;
        continue;
      }
      try {
        MemoryBlock table = currentProgram.getMemory().getBlock(frame.lsda);
        ExceptionReader reader = new ExceptionReader(frame.lsda, table.getEnd().add(1));
        int encoding = (int) reader.fixed(1);
        Address base =
            encoding == 255
                ? frame.start
                : exceptionPointer(reader.encoded(encoding, true), encoding);
        if (base == null) continue;
        if (reader.fixed(1) != 255) reader.leb(false);
        encoding = (int) reader.fixed(1);
        if ((encoding & 240) != 0) continue;
        ExceptionReader calls = reader.bounded(reader.leb(false));
        List<Address> pending = new ArrayList<>();
        while (calls.cursor.compareTo(calls.end) < 0) {
          calls.encoded(encoding, false);
          calls.encoded(encoding, false);
          long landing = calls.encoded(encoding, false);
          calls.leb(false);
          if (landing > 0) pending.add(base.add(landing));
        }
        AddressSet coverage = new AddressSet(function.getBody());
        AddressSet frameRange = new AddressSet(frame.start, frame.end.subtract(1));
        Set<Address> visited = new HashSet<>();
        for (int i = 0; i < pending.size(); ++i) {
          monitor.checkCancelled();
          Address pc = pending.get(i);
          if (!frameRange.contains(pc))
            throw new IllegalArgumentException("exception CFG leaves its FDE");
          if (!visited.add(pc)) continue;
          Function owner = currentProgram.getFunctionManager().getFunctionContaining(pc);
          if (owner != null && !owner.equals(function))
            throw new IllegalArgumentException("ambiguous exception function ownership");
          Instruction instruction = currentProgram.getListing().getInstructionAt(pc);
          if (instruction == null) {
            DisassembleCommand command = new DisassembleCommand(pc, frameRange, true);
            if (!command.applyTo(currentProgram, monitor))
              throw new IllegalArgumentException("undecodable exception entry");
            instruction = currentProgram.getListing().getInstructionAt(pc);
          }
          if (instruction == null || !frameRange.contains(instruction.getMaxAddress()))
            throw new IllegalArgumentException("invalid exception instruction");
          coverage.add(pc, instruction.getMaxAddress());
          // These ABI calls never return. Undiscovered landing-pad code may
          // still have a synthetic fallthrough into unreachable padding.
          String call = exceptionCall(instruction);
          if (call.equals("__cxa_throw")
              || call.equals("__cxa_rethrow")
              || call.equals("_Unwind_Resume")) continue;
          if (instruction.getDefaultFallThrough() != null)
            pending.add(instruction.getDefaultFallThrough());
          if (instruction
              .getPrototype()
              .getFlowType(instruction.getInstructionContext())
              .isJump()) {
            Address[] flows = instruction.getDefaultFlows();
            if (flows.length == 0) throw new IllegalArgumentException("indirect exception branch");
            for (Address target : flows) pending.add(target);
          }
        }
        if (!function.getBody().equals(coverage)) {
          function.setBody(coverage);
          decompiler.flushCache();
          analyzedFunctions.remove(function.getEntryPoint());
          recentAnalyses.remove(function.getEntryPoint());
        }
        if (coverage.contains(address)) return function;
      } catch (Exception error) {
        // Uncertain ownership or flow retains the original function boundary.
      }
    }
    return null;
  }

  private ExceptionFrame exceptionFrame(Address address) {
    for (ExceptionFrame frame : exceptionFrames()) {
      if (address.compareTo(frame.start) >= 0 && address.compareTo(frame.end) < 0) return frame;
    }
    return null;
  }

  private Instruction exceptionInstruction(Address pc, AddressSet allowed) {
    if (!allowed.contains(pc)) return null;
    Instruction instruction = currentProgram.getListing().getInstructionAt(pc);
    if (instruction == null) {
      // Decode only the proved instruction address, never an unconstrained
      // transitive function body when a cold landing pad was undiscovered.
      AddressRange range = allowed.getRangeContaining(pc);
      Address end = pc.add(14);
      if (end.compareTo(range.getMaxAddress()) > 0) end = range.getMaxAddress();
      DisassembleCommand command = new DisassembleCommand(pc, new AddressSet(pc, end), false);
      if (!command.applyTo(currentProgram, monitor)) return null;
      instruction = currentProgram.getListing().getInstructionAt(pc);
    }
    return instruction != null && allowed.contains(instruction.getMaxAddress())
        ? instruction
        : null;
  }

  private Function exceptionOwner(Address address) {
    ExceptionFrame target = exceptionFrame(address);
    if (target == null) return null;
    if (!exceptionOwnerAttempts.add(target.start)) return exceptionOwners.get(target.start);
    if (exceptionColdSources == null) {
      exceptionColdSources = new HashMap<>();
      // Index only direct cold-entry edges reachable from LSDA landing pads.
      // This module pass does no type demangling or handler recovery;
      // each query proves just the candidates that can reach its own FDE.
      for (ExceptionFrame source : exceptionFrames()) {
        try {
          MemoryBlock table = currentProgram.getMemory().getBlock(source.lsda);
          ExceptionReader reader = new ExceptionReader(source.lsda, table.getEnd().add(1));
          int encoding = (int) reader.fixed(1);
          Address base =
              encoding == 255
                  ? source.start
                  : exceptionPointer(reader.encoded(encoding, true), encoding);
          if (base == null) continue;
          if (reader.fixed(1) != 255) reader.leb(false);
          encoding = (int) reader.fixed(1);
          if ((encoding & 240) != 0) continue;
          ExceptionReader calls = reader.bounded(reader.leb(false));
          List<Address> pending = new ArrayList<>();
          while (calls.cursor.compareTo(calls.end) < 0) {
            calls.encoded(encoding, false);
            calls.encoded(encoding, false);
            long landing = calls.encoded(encoding, false);
            long action = calls.leb(false);
            if (landing > 0 && action > 0) pending.add(base.add(landing));
          }
          AddressSet allowed = new AddressSet(source.start, source.end.subtract(1));
          Set<Address> visited = new HashSet<>();
          for (int i = 0; i < pending.size(); ++i) {
            monitor.checkCancelled();
            Address pc = pending.get(i);
            if (!allowed.contains(pc)) continue;
            if (!visited.add(pc)) continue;
            Instruction instruction = exceptionInstruction(pc, allowed);
            if (instruction == null) continue;
            FlowType flow = exceptionFlow(instruction);
            if (flow.isCall()
                && (exceptionCall(instruction).equals("__cxa_begin_catch")
                    || !exceptionCallReturns(instruction))) continue;
            if (flow.isTerminal()) continue;
            if (instruction.getDefaultFallThrough() != null)
              pending.add(instruction.getDefaultFallThrough());
            if (flow.isJump() && !flow.isComputed()) {
              for (Address next : instruction.getDefaultFlows()) {
                if (allowed.contains(next)) pending.add(next);
                else if (!flow.isConditional() && exceptionFramesByEntry.containsKey(next))
                  exceptionColdSources.computeIfAbsent(next, unused -> new HashSet<>()).add(source);
              }
            }
          }
        } catch (Exception error) {
          // An invalid source cannot introduce a cold-owner candidate.
        }
      }
    }
    Function owner = null;
    for (ExceptionFrame frame : exceptionColdSources.getOrDefault(target.start, Set.of())) {
      Function candidate = currentProgram.getFunctionManager().getFunctionAt(frame.start);
      if (candidate == null || candidate.isExternal()) continue;
      AddressSet coverage = new AddressSet(candidate.getBody());
      JsonArray scopes = exceptionScopes(candidate, coverage);
      if (!coverage.contains(address)) continue;
      boolean handler = false;
      for (var value : scopes) {
        JsonObject scope = value.getAsJsonObject();
        if (!scope.get("kind").getAsString().equals("catch")) continue;
        for (var item : scope.getAsJsonArray("ranges")) {
          long start =
              Long.parseUnsignedLong(
                  item.getAsJsonObject().get("start").getAsString().substring(2), 16);
          Address pc = currentProgram.getImageBase().add(start - linkBase);
          handler |= pc.compareTo(target.start) >= 0 && pc.compareTo(target.end) < 0;
        }
      }
      if (!handler) continue;
      if (owner != null && !owner.equals(candidate)) return null;
      owner = candidate;
    }
    if (owner != null) exceptionOwners.put(target.start, owner);
    return owner;
  }

  private static FlowType exceptionFlow(Instruction instruction) {
    // Saved Ghidra projects may infer CALL_RETURN for a cold-partition JMP.
    // Exception ownership must be proved from the unchanged machine bytes.
    return instruction.getPrototype().getFlowType(instruction.getInstructionContext());
  }

  private String exceptionCall(Instruction instruction) {
    if (!exceptionFlow(instruction).isCall()) return "";
    Address[] flows = instruction.getDefaultFlows();
    if (flows.length != 1) return "";
    Function target = currentProgram.getFunctionManager().getFunctionAt(flows[0]);
    if (target != null && target.isThunk()) target = target.getThunkedFunction(true);
    if (target != null) return target.getName();
    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(flows[0]);
    return symbol == null ? "" : symbol.getName();
  }

  private boolean exceptionCallReturns(Instruction instruction) {
    Address[] flows = instruction.getDefaultFlows();
    if (flows.length != 1) return false;
    String name = exceptionCall(instruction);
    if (name.equals("__cxa_throw") || name.equals("__cxa_rethrow") || name.equals("_Unwind_Resume"))
      return false;
    Function target = currentProgram.getFunctionManager().getFunctionAt(flows[0]);
    if (target != null && target.isThunk()) target = target.getThunkedFunction(true);
    return target == null || !target.hasNoReturn();
  }

  private static final class ExceptionState {
    final Map<Address, Byte> registers = new HashMap<>();
    final Map<Address, Byte> temporaries = new HashMap<>();
    final Map<Long, Byte> stack = new HashMap<>();

    Long read(Varnode value) {
      if (value.getSize() > 8) return null;
      if (value.isConstant()) return value.getOffset();
      Map<Address, Byte> values = value.isUnique() ? temporaries : registers;
      long result = 0;
      for (int i = 0; i < value.getSize(); ++i) {
        Byte part = values.get(value.getAddress().add(i));
        if (part == null) return null;
        result |= (part & 255L) << (i * 8);
      }
      return result;
    }

    void write(Varnode output, Long value) {
      if (output == null) return;
      Map<Address, Byte> values = output.isUnique() ? temporaries : registers;
      for (int i = 0; i < output.getSize(); ++i) {
        if (value == null || i >= 8) values.remove(output.getAddress().add(i));
        else values.put(output.getAddress().add(i), (byte) (value >>> (i * 8)));
      }
    }
  }

  private ExceptionHandler exceptionCatch(
      AddressSet allowed, Address landing, int selector, AddressSet proof) throws Exception {
    ExceptionState state = new ExceptionState();
    for (String name : List.of("RDX", "RBP", "RSP")) {
      Register register = currentProgram.getRegister(name);
      if (register == null) return null;
      long initial =
          name.equals("RDX")
              ? selector
              : name.equals("RBP") ? 0x4000000000000000L : 0x5000000000000000L;
      state.write(new Varnode(register.getAddress(), register.getMinimumByteSize()), initial);
    }
    Set<Address> seen = new HashSet<>();
    Address pc = landing;
    boolean crossed = false;
    while (true) {
      if (!allowed.contains(pc) || !seen.add(pc)) return null;
      Instruction instruction = exceptionInstruction(pc, allowed);
      if (instruction == null || !allowed.contains(instruction.getMaxAddress())) return null;
      proof.add(instruction.getAddress(), instruction.getMaxAddress());
      if (exceptionFlow(instruction).isCall()) {
        String call = exceptionCall(instruction);
        if (call.equals("__cxa_begin_catch")) return new ExceptionHandler(pc, state);
        if (!exceptionCallReturns(instruction) || instruction.getDefaultFallThrough() == null)
          return null;
        // On a cleanup call's normal return only SysV callee-saved registers
        // survive. Its implementation may alter any remembered memory byte.
        // The ABI end_catch operation already has a separate spill policy.
        Set<Address> preserved = new HashSet<>();
        for (String name : List.of("RBX", "RBP", "RSP", "R12", "R13", "R14", "R15")) {
          Register register = currentProgram.getRegister(name);
          if (register != null)
            for (int i = 0; i < register.getMinimumByteSize(); ++i)
              preserved.add(register.getAddress().add(i));
        }
        state.registers.keySet().retainAll(preserved);
        if (!call.equals("__cxa_end_catch")) state.stack.clear();
        state.temporaries.clear();
        pc = instruction.getDefaultFallThrough();
        continue;
      }
      state.temporaries.clear();
      Address next = instruction.getDefaultFallThrough();
      PcodeOp[] ops = instruction.getPcode(false);
      for (int i = 0; i < ops.length; ++i) {
        PcodeOp op = ops[i];
        if (op.getOutput() != null && op.getOutput().isRegister()) {
          for (String name : List.of("RBP", "RSP")) {
            Register register = currentProgram.getRegister(name);
            Address output = op.getOutput().getAddress();
            if (output.compareTo(register.getAddress().add(register.getMinimumByteSize())) < 0
                && output.add(op.getOutput().getSize()).compareTo(register.getAddress()) > 0)
              return null;
          }
        }
        Long a = op.getNumInputs() > 0 ? state.read(op.getInput(0)) : null;
        Long b = op.getNumInputs() > 1 ? state.read(op.getInput(1)) : null;
        Long value = null;
        int size = op.getNumInputs() > 0 ? op.getInput(0).getSize() : 0;
        long mask = size < 8 ? (1L << (size * 8)) - 1 : -1L;
        switch (op.getOpcode()) {
          case PcodeOp.COPY, PcodeOp.INT_ZEXT -> value = a;
          case PcodeOp.INT_SEXT -> {
            if (a != null) value = size == 8 ? a : (a << (64 - size * 8)) >> (64 - size * 8);
          }
          case PcodeOp.INT_ADD -> {
            if (a != null && b != null) value = a + b;
          }
          case PcodeOp.INT_SUB -> {
            if (a != null && b != null) value = a - b;
          }
          case PcodeOp.INT_AND -> {
            if (a != null && b != null) value = a & b;
          }
          case PcodeOp.INT_OR -> {
            if (a != null && b != null) value = a | b;
          }
          case PcodeOp.INT_XOR -> {
            if (a != null && b != null) value = a ^ b;
          }
          case PcodeOp.INT_EQUAL -> {
            if (a != null && b != null) value = (a & mask) == (b & mask) ? 1L : 0L;
          }
          case PcodeOp.INT_NOTEQUAL -> {
            if (a != null && b != null) value = (a & mask) != (b & mask) ? 1L : 0L;
          }
          case PcodeOp.BOOL_NEGATE -> {
            if (a != null) value = a == 0 ? 1L : 0L;
          }
          case PcodeOp.BOOL_AND -> {
            if (a != null && b != null) value = a != 0 && b != 0 ? 1L : 0L;
          }
          case PcodeOp.BOOL_OR -> {
            if (a != null && b != null) value = a != 0 || b != 0 ? 1L : 0L;
          }
          case PcodeOp.SUBPIECE -> {
            if (a != null && b != null && b >= 0 && b < 8) value = a >>> (b * 8);
          }
          case PcodeOp.LOAD -> {
            if (b != null && op.getOutput().getSize() <= 8) {
              value = 0L;
              for (int j = 0; j < op.getOutput().getSize(); ++j) {
                Byte part = state.stack.get(b + j);
                if (part == null) {
                  value = null;
                  break;
                }
                value |= (part & 255L) << (j * 8);
              }
            }
          }
          case PcodeOp.STORE -> {
            Long stored = state.read(op.getInput(2));
            if (b == null) state.stack.clear();
            else
              for (int j = 0; j < op.getInput(2).getSize(); ++j) {
                if (stored == null || j >= 8) state.stack.remove(b + j);
                else state.stack.put(b + j, (byte) (stored >>> (j * 8)));
              }
          }
          case PcodeOp.BRANCH, PcodeOp.CBRANCH -> {
            if (op.getOpcode() == PcodeOp.CBRANCH && b == null) return null;
            if (op.getOpcode() == PcodeOp.BRANCH || b != 0) {
              if (op.getInput(0).isConstant()) {
                i += (int) op.getInput(0).getOffset() - 1;
                if (i < -1 || i >= ops.length) return null;
              } else {
                next = op.getInput(0).getAddress();
                i = ops.length;
              }
            }
          }
          case PcodeOp.BRANCHIND, PcodeOp.RETURN, PcodeOp.CALLIND, PcodeOp.CALLOTHER -> {
            return null;
          }
          default -> {}
        }
        state.write(op.getOutput(), value);
      }
      if (next == null) return null;
      if (!allowed.contains(next)) {
        ExceptionFrame target = exceptionFrame(next);
        if (crossed
            || target == null
            || !target.start.equals(next)
            || !exceptionFlow(instruction).isJump()
            || instruction
                .getPrototype()
                .getFlowType(instruction.getInstructionContext())
                .isConditional()
            || instruction.getDefaultFlows().length != 1
            || !instruction.getDefaultFlows()[0].equals(next)) return null;
        allowed.add(target.start, target.end.subtract(1));
        crossed = true;
      }
      pc = next;
    }
  }

  private AddressSet exceptionBody(AddressSet allowed, Address begin) {
    AddressSet body = new AddressSet();
    Map<Address, Set<Address>> predecessors = new HashMap<>();
    Set<Address> endings = new HashSet<>();
    List<Address> pending = new ArrayList<>();
    pending.add(begin);
    for (int i = 0; i < pending.size(); ++i) {
      Address pc = pending.get(i);
      if (body.contains(pc)) continue;
      Instruction instruction = exceptionInstruction(pc, allowed);
      if (instruction == null || !allowed.contains(instruction.getMaxAddress())) return null;
      body.add(instruction.getMinAddress(), instruction.getMaxAddress());
      String call = exceptionCall(instruction);
      if (call.equals("__cxa_end_catch") || call.equals("__cxa_rethrow")) {
        endings.add(pc);
        continue;
      }
      if (!pc.equals(begin) && (call.equals("__cxa_begin_catch") || call.equals("__cxa_throw")))
        return null;
      List<Address> successors = new ArrayList<>();
      if (instruction.getDefaultFallThrough() != null)
        successors.add(instruction.getDefaultFallThrough());
      if (exceptionFlow(instruction).isJump()) {
        if (instruction.getDefaultFlows().length == 0) return null;
        for (Address target : instruction.getDefaultFlows()) successors.add(target);
      }
      if (successors.isEmpty()
          || instruction
              .getPrototype()
              .getFlowType(instruction.getInstructionContext())
              .isTerminal()) return null;
      for (Address next : successors) {
        if (!allowed.contains(next)) return null;
        predecessors.computeIfAbsent(next, unused -> new HashSet<>()).add(pc);
        pending.add(next);
      }
    }
    // Reject escaping paths or detached infinite regions: every included
    // instruction must reach end_catch or the ABI noreturn rethrow boundary.
    Set<Address> closed = new HashSet<>();
    pending = new ArrayList<>(endings);
    for (int i = 0; i < pending.size(); ++i) {
      Address pc = pending.get(i);
      if (!closed.add(pc)) continue;
      pending.addAll(predecessors.getOrDefault(pc, Set.of()));
    }
    for (Instruction instruction : currentProgram.getListing().getInstructions(body, true)) {
      if (!closed.contains(instruction.getAddress())) return null;
    }
    return endings.isEmpty() ? null : body;
  }

  private Set<Address> exceptionUniformCatches(
      AddressSet allowed, Address landing, AddressSet proof) {
    List<Address> pending = new ArrayList<>();
    pending.add(landing);
    Set<Address> handlers = new HashSet<>();
    Set<Address> endings = new HashSet<>();
    Map<Address, Set<Address>> predecessors = new HashMap<>();
    for (int i = 0; i < pending.size(); ++i) {
      Address pc = pending.get(i);
      if (proof.contains(pc)) continue;
      Instruction instruction = exceptionInstruction(pc, allowed);
      if (instruction == null) return null;
      proof.add(pc, instruction.getMaxAddress());
      FlowType flow = exceptionFlow(instruction);
      String call = exceptionCall(instruction);
      if (flow.isCall()) {
        if (call.equals("__cxa_begin_catch")) {
          handlers.add(pc);
          endings.add(pc);
          continue;
        }
        if (call.equals("__cxa_throw")
            || call.equals("__cxa_rethrow")
            || call.equals("_Unwind_Resume")) {
          endings.add(pc);
          continue;
        }
        if (!exceptionCallReturns(instruction)) return null;
      } else {
        for (PcodeOp op : instruction.getPcode(false)) {
          if (op.getOutput() == null || !op.getOutput().isRegister()) continue;
          for (String name : List.of("RBP", "RSP")) {
            Register register = currentProgram.getRegister(name);
            Address output = op.getOutput().getAddress();
            if (output.compareTo(register.getAddress().add(register.getMinimumByteSize())) < 0
                && output.add(op.getOutput().getSize()).compareTo(register.getAddress()) > 0)
              return null;
          }
        }
      }
      if (flow.isTerminal() || flow.isComputed()) return null;
      List<Address> successors = new ArrayList<>();
      if (instruction.getDefaultFallThrough() != null)
        successors.add(instruction.getDefaultFallThrough());
      if (flow.isJump()) {
        if (instruction.getDefaultFlows().length == 0) return null;
        for (Address next : instruction.getDefaultFlows()) successors.add(next);
      }
      if (successors.isEmpty()) return null;
      for (Address next : successors) {
        if (!allowed.contains(next)) return null;
        predecessors.computeIfAbsent(next, unused -> new HashSet<>()).add(pc);
        pending.add(next);
      }
    }
    Set<Address> closed = new HashSet<>();
    pending = new ArrayList<>(endings);
    for (int i = 0; i < pending.size(); ++i) {
      Address pc = pending.get(i);
      if (closed.add(pc)) pending.addAll(predecessors.getOrDefault(pc, Set.of()));
    }
    for (Instruction instruction : currentProgram.getListing().getInstructions(proof, true))
      if (!closed.contains(instruction.getAddress())) return null;
    return handlers.isEmpty() ? null : handlers;
  }

  private JsonArray exceptionScopes(Function function, AddressSet instructions) {
    List<ExceptionScope> scopes = new ArrayList<>();
    List<ExceptionCandidate> catches = new ArrayList<>();
    exceptionFrames();
    for (ExceptionFrame frame :
        exceptionFramesByEntry.getOrDefault(function.getEntryPoint(), List.of())) {
      AddressSet allowed = new AddressSet(frame.start, frame.end.subtract(1));
      Set<String> frameTypes = new HashSet<>();
      Set<Address> unresolved = new HashSet<>();
      boolean uniform = true;
      try {
        MemoryBlock table = currentProgram.getMemory().getBlock(frame.lsda);
        ExceptionReader reader = new ExceptionReader(frame.lsda, table.getEnd().add(1));
        int lpEncoding = (int) reader.fixed(1);
        Address lpStart =
            lpEncoding == 255
                ? frame.start
                : exceptionPointer(reader.encoded(lpEncoding, true), lpEncoding);
        if (lpStart == null) continue;
        int typeEncoding = (int) reader.fixed(1);
        Address typeBase = null;
        if (typeEncoding != 255) {
          long offset = reader.leb(false);
          if (offset < 0 || offset > reader.end.subtract(reader.cursor)) continue;
          typeBase = reader.cursor.add(offset);
        }
        int callEncoding = (int) reader.fixed(1);
        if ((callEncoding & 240) != 0) continue;
        ExceptionReader calls = reader.bounded(reader.leb(false));
        Address actionBase = reader.cursor;
        while (calls.cursor.compareTo(calls.end) < 0) {
          long offset = calls.encoded(callEncoding, false);
          long length = calls.encoded(callEncoding, false);
          long landingOffset = calls.encoded(callEncoding, false);
          long action = calls.leb(false);
          if (action == 0) continue;
          if (offset < 0
              || length <= 0
              || landingOffset <= 0
              || action <= 0
              || typeBase == null
              || offset > frame.end.subtract(lpStart)
              || length > frame.end.subtract(lpStart) - offset) {
            uniform = false;
            continue;
          }
          Address start = lpStart.add(offset);
          Address end = start.add(length);
          Address landing = lpStart.add(landingOffset);
          Instruction last = currentProgram.getListing().getInstructionContaining(end.subtract(1));
          if (!allowed.contains(start, end.subtract(1))
              || !allowed.contains(landing)
              || currentProgram.getListing().getInstructionAt(start) == null
              || last == null
              || !last.getMaxAddress().add(1).equals(end)) {
            uniform = false;
            continue;
          }
          Map<Integer, String> types = new LinkedHashMap<>();
          Set<Address> seen = new HashSet<>();
          Address address = actionBase.add(action - 1);
          boolean valid = false;
          while (true) {
            if (address.compareTo(actionBase) < 0
                || address.compareTo(typeBase) >= 0
                || !seen.add(address)) break;
            ExceptionReader entry = new ExceptionReader(address, typeBase);
            long filter = entry.leb(true);
            Address displacement = entry.cursor;
            long next = entry.leb(true);
            if (filter < 0 || filter > Integer.MAX_VALUE) break;
            if (filter > 0) {
              int width =
                  switch (typeEncoding & 15) {
                    case 0, 4, 12 -> 8;
                    case 2, 10 -> 2;
                    case 3, 11 -> 4;
                    default -> 0;
                  };
              if (width == 0 || filter > typeBase.subtract(actionBase) / width) break;
              Address typeAddress = typeBase.subtract(width * filter);
              ExceptionReader type = new ExceptionReader(typeAddress, typeBase);
              String name =
                  exceptionType(typeAddress, type.encoded(typeEncoding, true), typeEncoding);
              if (name == null) break;
              types.put((int) filter, name);
            }
            if (next == 0) {
              valid = true;
              break;
            }
            address = displacement.add(next);
          }
          if (!valid) {
            uniform = false;
            continue;
          }
          if (types.isEmpty()) continue;
          frameTypes.addAll(types.values());
          scopes.add(
              new ExceptionScope(
                  "try", "try {", new AddressSet(start, end.subtract(1)), null, 0, 0, 0));
          for (var type : types.entrySet()) {
            AddressSet proof = new AddressSet();
            AddressSet dispatch = new AddressSet(allowed);
            ExceptionHandler handler = exceptionCatch(dispatch, landing, type.getKey(), proof);
            if (handler == null) {
              unresolved.add(landing);
              continue;
            }
            Address begin = handler.entry;
            AddressSet body = exceptionBody(dispatch, begin);
            if (body == null) continue;
            ExceptionFrame handlerFrame = exceptionFrame(begin);
            if (handlerFrame != null && !handlerFrame.equals(frame)) {
              Function handlerFunction =
                  currentProgram.getFunctionManager().getFunctionAt(handlerFrame.start);
              if (handlerFunction != null)
                proof.add(
                    handlerFunction
                        .getBody()
                        .intersectRange(handlerFrame.start, handlerFrame.end.subtract(1)));
            }
            String text = "catch (" + type.getValue() + ") {";
            catches.add(new ExceptionCandidate(handler, text, body, proof));
          }
        }
      } catch (Exception error) {
        uniform = false;
        // Keep raw assembly for unproved or unsupported LSDA records.
      }
      // A cleanup call can erase the selector's spilled value. Only when every
      // action in this FDE names the same catch type may branch reachability
      // determine its handlers without guessing that missing selector value.
      if (uniform && frameTypes.size() == 1) {
        String text = "catch (" + frameTypes.iterator().next() + ") {";
        for (Address landing : unresolved) {
          AddressSet proof = new AddressSet();
          Set<Address> handlers = exceptionUniformCatches(allowed, landing, proof);
          if (handlers == null) continue;
          for (Address begin : handlers) {
            AddressSet body = exceptionBody(allowed, begin);
            if (body == null) continue;
            catches.add(
                new ExceptionCandidate(new ExceptionHandler(begin, null), text, body, proof));
          }
        }
      }
    }
    // Clang can share begin_catch and end_catch between distinct handlers.
    // A type-specific range alone cannot identify which handler is running.
    // Carry a proven selector value at begin_catch; the consumer retains that
    // selection through the shared tail even after ABI calls clobber registers.
    List<String> registers =
        List.of(
            "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12",
            "R13", "R14", "R15");
    for (ExceptionCandidate candidate : catches) {
      List<ExceptionCandidate> peers =
          catches.stream()
              .filter(other -> other.handler.entry.equals(candidate.handler.entry))
              .toList();
      boolean shared = peers.stream().anyMatch(other -> !other.text.equals(candidate.text));
      int selectorRegister = 0, selectorBytes = 0;
      long selectorValue = 0;
      if (shared) {
        search:
        for (int registerIndex = 0; registerIndex < registers.size(); ++registerIndex) {
          Register register = currentProgram.getRegister(registers.get(registerIndex));
          if (register == null) continue;
          for (int width : List.of(8, 4, 2, 1)) {
            Varnode value = new Varnode(register.getAddress(), width);
            boolean distinguishes = true;
            for (ExceptionCandidate left : peers) {
              Long a = left.handler.state == null ? null : left.handler.state.read(value);
              if (a == null) {
                distinguishes = false;
                break;
              }
              for (ExceptionCandidate right : peers) {
                if (left.text.equals(right.text)) continue;
                Long b = right.handler.state == null ? null : right.handler.state.read(value);
                if (b == null || a.equals(b)) {
                  distinguishes = false;
                  break;
                }
              }
              if (!distinguishes) break;
            }
            if (!distinguishes) continue;
            selectorRegister = registerIndex + 1;
            selectorBytes = width;
            selectorValue = candidate.handler.state.read(value);
            break search;
          }
        }
        if (selectorRegister == 0) continue;
      }
      scopes.add(
          new ExceptionScope(
              "catch",
              candidate.text,
              candidate.body,
              candidate.handler.entry,
              selectorRegister,
              selectorBytes,
              selectorValue));
      instructions.add(candidate.body);
      instructions.add(candidate.proof);
    }
    // Equal records share value equality: rejecting a duplicate later would
    // otherwise reject its first occurrence as well.
    scopes = new ArrayList<>(new LinkedHashSet<>(scopes));
    scopes.sort(
        java.util.Comparator.comparing((ExceptionScope scope) -> scope.ranges.getMinAddress())
            .thenComparing(scope -> scope.kind)
            .thenComparing(scope -> scope.text));
    JsonArray result = new JsonArray();
    Set<ExceptionScope> rejected = new HashSet<>();
    for (int i = 0; i < scopes.size(); ++i) {
      ExceptionScope left = scopes.get(i);
      for (int j = 0; j < scopes.size(); ++j) {
        if (i == j) continue;
        ExceptionScope right = scopes.get(j);
        if (left.entry != null && right.entry != null) {
          // Separate catch entries cannot execute together: body recovery
          // rejects a path entering another begin_catch. A common entry must
          // instead distinguish its alternatives with one proven selector.
          if (!left.entry.equals(right.entry)
              && !left.ranges.contains(right.entry)
              && !right.ranges.contains(left.entry)) continue;
          if (left.entry.equals(right.entry)
              && left.selectorRegister != 0
              && left.selectorRegister == right.selectorRegister
              && left.selectorBytes == right.selectorBytes
              && left.selectorValue != right.selectorValue) continue;
        }
        if (left.ranges.equals(right.ranges)) {
          rejected.add(left);
          rejected.add(right);
        } else if (left.ranges.intersects(right.ranges)
            && !left.ranges.contains(right.ranges)
            && !right.ranges.contains(left.ranges)) {
          rejected.add(left);
          rejected.add(right);
        }
      }
    }
    for (ExceptionScope scope : scopes) {
      if (rejected.contains(scope)) continue;
      JsonObject record = new JsonObject();
      record.addProperty("id", "0x" + Integer.toHexString(result.size() + 1));
      record.addProperty("kind", scope.kind);
      record.addProperty("text", scope.text);
      if (scope.entry != null) {
        record.addProperty("entry", elfAddress(scope.entry));
        if (scope.selectorRegister != 0) {
          JsonObject selector = new JsonObject();
          selector.addProperty("register", scope.selectorRegister);
          selector.addProperty("bytes", scope.selectorBytes);
          selector.addProperty("value", "0x" + Long.toUnsignedString(scope.selectorValue, 16));
          record.add("selector", selector);
        }
      }
      JsonArray ranges = new JsonArray();
      for (AddressRange range : scope.ranges.getAddressRanges()) {
        JsonObject item = new JsonObject();
        item.addProperty("start", elfAddress(range.getMinAddress()));
        item.addProperty("end", elfAddress(range.getMaxAddress().add(1)));
        ranges.add(item);
      }
      record.add("ranges", ranges);
      instructions.add(scope.ranges);
      result.add(record);
    }
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
    Function function = exceptionOwner(address);
    if (function == null) function = exceptionFunction(address, decompiler);
    if (function == null)
      function = currentProgram.getFunctionManager().getFunctionContaining(address);
    if (function == null) {
      for (ExceptionFrame frame : exceptionFrames()) {
        if (address.compareTo(frame.start) >= 0 && address.compareTo(frame.end) < 0) {
          Function owner = currentProgram.getFunctionManager().getFunctionAt(frame.start);
          if (owner != null && !owner.isExternal()) {
            function = owner;
            break;
          }
        }
      }
    }
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
      decompiled = decompiler.decompileFunction(function, 0, monitor);
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
                    conditional)
                : null;
        if (text != null && !text.isEmpty()) {
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
    AddressSet exportedBody = new AddressSet(function.getBody());
    JsonArray exceptions = exceptionScopes(function, exportedBody);
    JsonArray ranges = new JsonArray();
    for (AddressRange range : exportedBody.getAddressRanges()) {
      JsonObject item = new JsonObject();
      item.addProperty("start", elfAddress(range.getMinAddress()));
      item.addProperty("end", elfAddress(range.getMaxAddress().add(1)));
      ranges.add(item);
    }
    result.addProperty("ok", true);
    result.addProperty("entry", elfAddress(function.getEntryPoint()));
    result.addProperty("end", elfAddress(exportedBody.getMaxAddress().add(1)));
    result.add("ranges", ranges);
    result.add("lines", lines);
    result.add("controls", controls);
    result.add("exceptions", exceptions);
    if (level.equals("full")) {
      result.add("variables", variables(decompiled.getHighFunction(), function, depths));
      result.add("types", typeRecords);
    }
    result.add("return", returnRecord(decompiled.getHighFunction(), function));
    JsonArray instructions = new JsonArray();
    for (Instruction instruction :
        currentProgram.getListing().getInstructions(exportedBody, true)) {
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
    DecompileOptions options = new DecompileOptions();
    // Ghidra exposes signed-int limits, not an unlimited sentinel. Use its
    // representable range; the payload API converts whole MiB to an int byte count.
    options.setMaxInstructions(Integer.MAX_VALUE);
    options.setMaxJumpTableEntries(Integer.MAX_VALUE);
    options.setMaxPayloadMBytes(Integer.MAX_VALUE >>> 20);
    decompiler.setOptions(options);
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
      output.write("{\"ready\":true}\n");
      output.flush();
      String line;
      while ((line = input.readLine()) != null) {
        JsonObject response;
        try {
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
