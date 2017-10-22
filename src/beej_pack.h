/*
**  http://beej.us/guide/bgnet/output/html/multipage/advanced.html#serialization
*/

#ifndef BEEJ_PACK_H__
#define BEEJ_PACK_H__

unsigned int beej_pack(unsigned char *buf, char *format, ...);
void beej_unpack(const unsigned char *buf, char *format, ...);

#endif
