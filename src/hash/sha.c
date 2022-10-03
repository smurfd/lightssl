//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#include "sha.h"
#include "constants.h"

//
//
int SHA512Reset(SHA512Context *c) {
  if (!c) return shaNull;
  c->Message_Block_Index = 0;
  c->Length_High = c->Length_Low = 0;

  for (int i = 0; i < SHA512HashSize / 8; i++)
    c->imh[i] = SHA512_H0[i];

  c->Computed = 0;
  c->Corrupted = shaSuccess;

  return shaSuccess;
}

//
//
static void SHA_ProcessMessageBlock(SHA512Context *c) {
  u64 A, B, C, D, E, F, G, H, W[80], temp1, temp2;
  int t, t8;
  
  // Initialize the first 16 words in the array W
  for (t = t8 = 0; t < 16; t++, t8 += 8) W[t] = 
    ((u64)(c->mb[t8    ]) << 56) |
    ((u64)(c->mb[t8 + 1]) << 48) |
    ((u64)(c->mb[t8 + 2]) << 40) |
    ((u64)(c->mb[t8 + 3]) << 32) |
    ((u64)(c->mb[t8 + 4]) << 24) |
    ((u64)(c->mb[t8 + 5]) << 16) |
    ((u64)(c->mb[t8 + 6]) <<  8) |
    ((u64)(c->mb[t8 + 7]));

  for (t = 16; t < 80; t++)
    W[t] = SHA_s1(W[t-2]) + W[t-7] + SHA_s0(W[t-15]) + W[t-16];
  A = c->imh[0];
  B = c->imh[1];
  C = c->imh[2];
  D = c->imh[3];
  E = c->imh[4];
  F = c->imh[5];
  G = c->imh[6];
  H = c->imh[7];

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

  c->imh[0] += A;
  c->imh[1] += B;
  c->imh[2] += C;
  c->imh[3] += D;
  c->imh[4] += E;
  c->imh[5] += F;
  c->imh[6] += G;
  c->imh[7] += H;

  c->Message_Block_Index = 0;
}

//
//
int SHA512Input(SHA512Context *c, const u08 *message_array,
  unsigned int length) {
  uint64_t tmp;

  if (!c) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (c->Computed) return c->Corrupted = shaStateError;
  if (c->Corrupted) return c->Corrupted;

  while (length--) {
    c->mb[c->Message_Block_Index++] = *message_array;
    if ((SHA_AddLength(c, 8, tmp) == shaSuccess) &&
      (c->Message_Block_Index == SHA512_Message_Block_Size))
      SHA_ProcessMessageBlock(c);

    message_array++;
  }

  return c->Corrupted;
}

//
//
static void SHA_PadMessage(SHA512Context *c, u08 Pad_Byte) {
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (c->Message_Block_Index >= (SHA512_Message_Block_Size-16)) {
    c->mb[c->Message_Block_Index++] = Pad_Byte;
    while (c->Message_Block_Index < SHA512_Message_Block_Size)
      c->mb[c->Message_Block_Index++] = 0;

    SHA_ProcessMessageBlock(c);
  } else
    c->mb[c->Message_Block_Index++] = Pad_Byte;

  while (c->Message_Block_Index < (SHA512_Message_Block_Size-16))
    c->mb[c->Message_Block_Index++] = 0;

  c->mb[112] = (u08)(c->Length_High >> 56);
  c->mb[113] = (u08)(c->Length_High >> 48);
  c->mb[114] = (u08)(c->Length_High >> 40);
  c->mb[115] = (u08)(c->Length_High >> 32);
  c->mb[116] = (u08)(c->Length_High >> 24);
  c->mb[117] = (u08)(c->Length_High >> 16);
  c->mb[118] = (u08)(c->Length_High >> 8);
  c->mb[119] = (u08)(c->Length_High);

  c->mb[120] = (u08)(c->Length_Low >> 56);
  c->mb[121] = (u08)(c->Length_Low >> 48);
  c->mb[122] = (u08)(c->Length_Low >> 40);
  c->mb[123] = (u08)(c->Length_Low >> 32);
  c->mb[124] = (u08)(c->Length_Low >> 24);
  c->mb[125] = (u08)(c->Length_Low >> 16);
  c->mb[126] = (u08)(c->Length_Low >> 8);
  c->mb[127] = (u08)(c->Length_Low);

  SHA_ProcessMessageBlock(c);
}

//
//
static void SHA_Finalize(SHA512Context *c, u08 Pad_Byte) {
  SHA_PadMessage(c, Pad_Byte);
  // Clear message
  for (int_least16_t i = 0; i < SHA512_Message_Block_Size; ++i) c->mb[i] = 0;

  c->Length_High = c->Length_Low = 0;
  c->Computed = 1;
}

//
//
int SHA512Result(SHA512Context *c, u08 Message_Digest[SHA512HashSize]) {
  if (!c) return shaNull;
  if (!Message_Digest) return shaNull;
  if (c->Corrupted) return c->Corrupted;
  if (!c->Computed) SHA_Finalize(c, 0x80);

  for (int i = 0; i < SHA512HashSize; ++i)
    Message_Digest[i] = (u08)(c->imh[i>>3] >> 8 * (7 - (i % 8)));

  return shaSuccess;
}

//
//
int SHA512FinalBits(SHA512Context *c, u08 message_bits, unsigned int length) {
  uint64_t tmp;

  if (!c) return shaNull;
  if (!length) return shaSuccess;
  if (c->Corrupted) return c->Corrupted;
  if (c->Computed) return c->Corrupted = shaStateError;
  if (length >= 8) return c->Corrupted = shaBadParam;

  SHA_AddLength(c, length, tmp);
  SHA_Finalize(c, (u08)
    ((message_bits & masks[length]) | markbit[length]));

  return c->Corrupted;
}
