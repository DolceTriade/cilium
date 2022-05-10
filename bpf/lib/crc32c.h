#ifndef CRC32C_H_
#define CRC32C_H_

#define Polynomial 0x82F63B78


static __inline __u32 crc32c(__u8 *data, __u8* end)
{
  __u32 r = ~0;
  __u32 i = 0;
 
  for (;data < end; ++data)
  {
    r ^= *data;
 
    for(i = 0; i < 8; i++)
    {
      __u32 t = ~((r&1) - 1); r = (r>>1) ^ (Polynomial & t);
    }
  }
 
  return ~r;
}

#endif /* CRC32C_H_ */