#include "kernel_gate.h"

const ct_kernel_gate_template &ct_kernel_gate() {
  static constexpr ct_kernel_gate_template gate = {
      {
          0x9c,                         //  0: pushfq
          0x50,                         //  1: push %rax
          0xe8, 0x00, 0x00, 0x00, 0x00, //  2: call selector
          0x85, 0xc0,                   //  7: test %eax, %eax
          0x74, 0x13,                   //  9: je arm (30)
          0x83, 0xf8, 0x01,             // 11: cmp $1, %eax
          0x74, 0x07,                   // 14: je perfetto (23)
          0x58,                         // 16: full: pop %rax
          0x9d,                         // 17: popfq
          0xe9, 0x00, 0x00, 0x00, 0x00, // 18: jmp full continuation
          0x58,                         // 23: perfetto: pop %rax
          0x9d,                         // 24: popfq
          0xe9, 0x00, 0x00, 0x00, 0x00, // 25: jmp perfetto continuation
          0x58,                         // 30: arm: pop %rax
          0x9d,                         // 31: popfq
          0xe9, 0x00, 0x00, 0x00, 0x00, // 32: jmp arm continuation
      },
      {2, 3, 4, 7},
      {{{32, 33, 4, 37}, {25, 26, 4, 30}, {18, 19, 4, 23}}},
      {{{0, 0},
        {1, -8},
        {2, -16},
        {7, -16},
        {9, -16},
        {11, -16},
        {14, -16},
        {16, -16},
        {17, -8},
        {18, 0},
        {23, -16},
        {24, -8},
        {25, 0},
        {30, -16},
        {31, -8},
        {32, 0}}},
  };
  return gate;
}
