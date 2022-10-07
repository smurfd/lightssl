//                                                                            //
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
#define TEST1 "abc"
#define TEST2_2a "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
#define TEST2_2b "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
#define TEST2_2 TEST2_2a TEST2_2b
#define TEST3 "a"
#define TEST4a "01234567012345670123456701234567"
#define TEST4b "01234567012345670123456701234567"
#define TEST4 TEST4a TEST4b

#define TEST7_512 "\x08\xec\xb5\x2e\xba\xe1\xf7\x42\x2d\xb6\x2b\xcd\x54\x26\x70"
#define TEST8_512 \
  "\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0"
#define TEST9_512                                                            \
  "\x3a\xdd\xec\x85\x59\x32\x16\xd1\x61\x9a\xa0\x2d\x97\x56\x97\x0b\xfc\x70" \
  "\xac\xe2\x74\x4f\x7c\x6b\x27\x88\x15\x10\x28\xf7\xb6\xa2\x55\x0f\xd7\x4a" \
  "\x7e\x6e\x69\xc2\xc9\xb4\x5f\xc4\x54\x96\x6d\xc3\x1d\x2e\x10\xda\x1f\x95" \
  "\xce\x02\xbe\xb4\xbf\x87\x65\x57\x4c\xbd\x6e\x83\x37\xef\x42\x0a\xdc\x98" \
  "\xc1\x5c\xb6\xd5\xe4\xa0\x24\x1b\xa0\x04\x6d\x25\x0e\x51\x02\x31\xca\xc2" \
  "\x04\x6c\x99\x16\x06\xab\x4e\xe4\x14\x5b\xee\x2f\xf4\xbb\x12\x3a\xab\x49" \
  "\x8d\x9d\x44\x79\x4f\x99\xcc\xad\x89\xa9\xa1\x62\x12\x59\xed\xa7\x0a\x5b" \
  "\x6d\xd4\xbd\xd8\x77\x78\xc9\x04\x3b\x93\x84\xf5\x49\x06"
#define TEST10_512                                                           \
  "\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31\xa2\x30" \
  "\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde\x69\x74\xbf\x49" \
  "\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4\x93\x60\xc3\xe8\x7a\xf5" \
  "\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2\xf8\x68\x00\x2b\xc3\xe4\x31\xed" \
  "\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69" \
  "\x4f\xcb\xba\xf8\x8d\x95\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea" \
  "\x95\xbc\x44\x65\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d" \
  "\xc3\x2f\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41" \
  "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28\x35\x13" \
  "\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1\xf8\xb2\x46\xf1" \
  "\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8\xbf\x16\xf2\x68\xd6\x4f" \
  "\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51" \
  "\x86\x3a\x96\xc9\x49\xad\x47\xd7\xfb\x40\xd2"
#define TEST42 "smurfd"

#define TESTCOUNT 11
#define HASHCOUNT 1
#define HMACTESTCOUNT 7
#define length(x) (sizeof(x) - 1)

struct hash {
  int hashsize;
  struct {
    const char* testarray;
    int length;
    long repeatcount;
    int extrabits;
    int nr_extrabits;
    const char* res_arr;
  } t[TESTCOUNT];
} h = {sha_hsh_sz,
       {{TEST1, length(TEST1), 1, 0, 0,
         "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A21929"
         "92A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"},
        {TEST2_2, length(TEST2_2), 1, 0, 0,
         "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D2"
         "89E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"},
        {TEST3, length(TEST3), 1000000, 0, 0,
         "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF"
         "244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B"},
        {TEST4, length(TEST4), 10, 0, 0,
         "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024DB872D1ABD2BA8141A0F8"
         "5072A9BE1E2AA04CF33C765CB510813A39CD5A84C4ACAA64D3F3FB7BAE9"},
        {"", 0, 0, 0xB0, 5,
         "D4EE29A9E90985446B913CF1D1376C836F4BE2C1CF3CADA0720A6BF4857D886A7ECB3"
         "C4E4C0FA8C7F95214E41DC1B0D21B22A84CC03BF8CE4845F34DD5BDBAD4"},
        {"\xD0", 1, 1, 0, 0,
         "9992202938E882E73E20F6B69E68A0A7149090423D93C81BAB3F21678D4ACEEEE50E4"
         "E8CAFADA4C85A54EA8306826C4AD6E74CECE9631BFA8A549B4AB3FBBA15"},
        {TEST7_512, length(TEST7_512), 1, 0x80, 3,
         "ED8DC78E8B01B69750053DBB7A0A9EDA0FB9E9D292B1ED715E80A7FE290A4E16664FD"
         "913E85854400C5AF05E6DAD316B7359B43E64F8BEC3C1F237119986BBB6"},
        {TEST8_512, length(TEST8_512), 1, 0, 0,
         "CB0B67A4B8712CD73C9AABC0B199E9269B20844AFB75ACBDD1C153C9828924C3DDEDA"
         "AFE669C5FDD0BC66F630F6773988213EB1B16F517AD0DE4B2F0C95C90F8"},
        {TEST9_512, length(TEST9_512), 1, 0x80, 3,
         "32BA76FC30EAA0208AEB50FFB5AF1864FDBF17902A4DC0A682C61FCEA6D92B783267B"
         "21080301837F59DE79C6B337DB2526F8A0A510E5E53CAFED4355FE7C2F1"},
        {TEST10_512, length(TEST10_512), 1, 0, 0,
         "C665BEFB36DA189D78822D10528CBF3B12B3EEF726039909C1A16A270D48719377966"
         "B957A878E720584779A62825C18DA26415E49A7176A894E7510FD1451F5"},
        {TEST42, length(TEST42), 1, 0, 0,
         "555CFC37FC24D4971DE9B091EF13401B8C5CB8B5B55804DA571FB201CBB4FC5D147AC"
         "6F528656456651606546CA42A1070BDFD79D024F3B97DD1BDAC7E70F3D1"}}};

// Test arrays for HMAC.
struct hmachash {
  const char* keyarray[5];
  int keylength[5];
  const char* dataarray[5];
  int datalength[5];
  const char* res_arr[5];
  int res_len[5];
} hm[HMACTESTCOUNT] = {
    // "Hi There"
    {{"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
      "\x0b\x0b"},
     {20},
     {"\x48\x69\x20\x54\x68\x65\x72\x65"},
     {8},
     {"87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7"
      "D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854"},
     {sha_hsh_sz}},
    // "Jefe"
    {{"\x4a\x65\x66\x65"},
     {4},
     {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f"
      "\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f"},
     {28},
     {"164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75"
      "C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737"},
     {sha_hsh_sz}},
    {{"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa"},
     {20},
     {"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
      "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
      "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"},
     {50},
     {"FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E8482"
      "79A722C806B485A47E67C807B946A337BEE8942674278859E13292FB"},
     {sha_hsh_sz}},
    {{"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12"
      "\x13\x14\x15\x16\x17\x18\x19"},
     {25},
     {"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
      "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
      "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"},
     {50},
     {"B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C1"
      "1AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD"},
     {sha_hsh_sz}},
    {{"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
      "\x0c\x0c"},
     {20},
     {"Test With Truncation"},
     {20},
     {"415FAD6271580A531D4179BC891D87A6"},
     {16}},
    {{"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa"},
     {80, 131},
     {"Test Using Larger Than Block-Size Key - Hash Key First"},
     {54},
     {"80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037"
      "E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598"},
     {sha_hsh_sz}},
    {{"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xaa"},
     {80, 131},
     {"Test Using Larger Than Block-Size Key and Larger Than One Block-Size "
      "Data",
      "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69"
      "\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62"
      "\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20"
      "\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63"
      "\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b"
      "\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73"
      "\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75"
      "\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c"
      "\x67\x6f\x72\x69\x74\x68\x6d\x2e"},
     {73, 152},
     {"E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC"
      "3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58"},
     {sha_hsh_sz}}};
