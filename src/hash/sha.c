//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include "sha.h"
#include "constants.h"

//
//
int SHA512Reset(SHA512Context *context) {
  if (!context) return shaNull;
  context->Message_Block_Index = 0;
  context->Length_High = context->Length_Low = 0;

  for (int i = 0; i < SHA512HashSize/8; i++)
    context->Intermediate_Hash[i] = SHA512_H0[i];

  context->Computed = 0;
  context->Corrupted = shaSuccess;

  return shaSuccess;
}

//
//
static void SHA_ProcessMessageBlock(SHA512Context *context) {
  int        t, t8;                   /* Loop counter */
  uint64_t   temp1, temp2;            /* Temporary word value */
  uint64_t   W[80];                   /* Word sequence */
  uint64_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t8 = 0; t < 16; t++, t8 += 8)
    W[t] = ((uint64_t)(context->Message_Block[t8  ]) << 56) |
           ((uint64_t)(context->Message_Block[t8 + 1]) << 48) |
           ((uint64_t)(context->Message_Block[t8 + 2]) << 40) |
           ((uint64_t)(context->Message_Block[t8 + 3]) << 32) |
           ((uint64_t)(context->Message_Block[t8 + 4]) << 24) |
           ((uint64_t)(context->Message_Block[t8 + 5]) << 16) |
           ((uint64_t)(context->Message_Block[t8 + 6]) << 8) |
           ((uint64_t)(context->Message_Block[t8 + 7]));

  for (t = 16; t < 80; t++)
    W[t] = SHA_s1(W[t-2]) + W[t-7] + SHA_s0(W[t-15]) + W[t-16];
  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 80; t++) {
    temp1 = H + SHA_S1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA_S0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}

//
//
int SHA512Input(SHA512Context *context, const uint8_t *message_array,
  unsigned int length) {
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] = *message_array;
    if ((SHA_AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA512_Message_Block_Size))
      SHA_ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

//
//
static void SHA_PadMessage(SHA512Context *context, uint8_t Pad_Byte) {
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA512_Message_Block_Size-16)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA512_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA_ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA512_Message_Block_Size-16))
    context->Message_Block[context->Message_Block_Index++] = 0;

  context->Message_Block[112] = (uint8_t)(context->Length_High >> 56);
  context->Message_Block[113] = (uint8_t)(context->Length_High >> 48);
  context->Message_Block[114] = (uint8_t)(context->Length_High >> 40);
  context->Message_Block[115] = (uint8_t)(context->Length_High >> 32);
  context->Message_Block[116] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[117] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[118] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[119] = (uint8_t)(context->Length_High);

  context->Message_Block[120] = (uint8_t)(context->Length_Low >> 56);
  context->Message_Block[121] = (uint8_t)(context->Length_Low >> 48);
  context->Message_Block[122] = (uint8_t)(context->Length_Low >> 40);
  context->Message_Block[123] = (uint8_t)(context->Length_Low >> 32);
  context->Message_Block[124] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[125] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[126] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[127] = (uint8_t)(context->Length_Low);

  SHA_ProcessMessageBlock(context);
}

//
//
static void SHA_Finalize(SHA512Context *context, uint8_t Pad_Byte) {
  SHA_PadMessage(context, Pad_Byte);
  /* message may be sensitive, clear it out */
  for (int_least16_t i = 0; i < SHA512_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;

  context->Length_High = context->Length_Low = 0;
  context->Computed = 1;
}

//
//
int SHA512Result(SHA512Context *context, uint8_t Message_Digest[SHA512HashSize]) {
  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (!context->Computed) SHA_Finalize(context, 0x80);

  for (int i = 0; i < SHA512HashSize; ++i)
    Message_Digest[i] = (uint8_t)(context->Intermediate_Hash[i>>3] >> 8 * (7 - (i % 8)));

  return shaSuccess;
}

//
//
int SHA512FinalBits(SHA512Context *context,
                    uint8_t message_bits, unsigned int length) {
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (length >= 8) return context->Corrupted = shaBadParam;

  SHA_AddLength(context, length);
  SHA_Finalize(context, (uint8_t)
    ((message_bits & masks[length]) | markbit[length]));

  return context->Corrupted;
}