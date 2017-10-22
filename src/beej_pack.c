#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#include "beej_pack.h"

#define pack754_16(f) (pack754((f), 16, 5))
#define pack754_32(f) (pack754((f), 32, 8))
#define unpack754_16(i) (unpack754((i), 16, 5))
#define pack754_64(f) (pack754((f), 64, 11))
#define unpack754_32(i) (unpack754((i), 32, 8))
#define unpack754_64(i) (unpack754((i), 64, 11))


static unsigned char NUL_BYT_ORD = '\0';

static uint64_t pack754(long double f, unsigned bits, unsigned expbits);
static long double unpack754(uint64_t i, unsigned bits, unsigned expbits);
static void packi16(unsigned char *buf, unsigned int i, const unsigned char bytodr);
static void packi16_little(unsigned char *buf, unsigned int i);
static void packi32(unsigned char *buf, unsigned long int i, const unsigned char bytodr);
static void packi32_little(unsigned char *buf, unsigned long int i);
static void packi64(unsigned char *buf, unsigned long long int i, const unsigned char bytodr);
static void packi64_little(unsigned char *buf, unsigned long long int i);
static int unpacki16(const unsigned char *buf, const unsigned char bytodr);
static int unpacki16_big(const unsigned char *buf);
static int unpacki16_little(const unsigned char *buf);
static unsigned int unpacku16(const unsigned char *buf, const unsigned char bytodr);
static unsigned int unpacku16_big(const unsigned char *buf);
static unsigned int unpacku16_little(const unsigned char *buf);
static long int unpacki32(const unsigned char *buf, const unsigned char bytodr);
static long int unpacki32_big(const unsigned char *buf);
static long int unpacki32_little(const unsigned char *buf);
static unsigned long int unpacku32(const unsigned char *buf, const unsigned char bytodr);
static unsigned long int unpacku32_big(const unsigned char *buf);
static unsigned long int unpacku32_little(const unsigned char *buf);
static long long int unpacki64(const unsigned char *buf, const unsigned char bytodr);
static unsigned long long int unpacku64(const unsigned char *buf, const unsigned char bytodr);
static long long int unpacki64_little(const unsigned char *buf);
static long long int unpacki64_big(const unsigned char *buf);
static long long int unpacku64_little(const unsigned char *buf);
static long long int unpacku64_big(const unsigned char *buf);

uint64_t pack754(long double f, unsigned bits, unsigned expbits)
{
    long double fnorm;
    int shift;
    long long sign, exp, significand;
    unsigned significandbits = bits - expbits - 1; // -1 for sign bit

    if (f == 0.0) return 0; // get this special case out of the way

    // check sign and begin normalization
    if (f < 0) { sign = 1; fnorm = -f; }
    else { sign = 0; fnorm = f; }

    // get the normalized form of f and track the exponent
    shift = 0;
    while(fnorm >= 2.0) { fnorm /= 2.0; shift++; }
    while(fnorm < 1.0) { fnorm *= 2.0; shift--; }
    fnorm = fnorm - 1.0;

    // calculate the binary form (non-float) of the significand data
    significand = fnorm * ((1LL<<significandbits) + 0.5f);

    // get the biased exponent
    exp = shift + ((1<<(expbits-1)) - 1); // shift + bias

    // return the final answer
    return (sign<<(bits-1)) | (exp<<(bits-expbits-1)) | significand;
}

long double unpack754(uint64_t i, unsigned bits, unsigned expbits)
{
    long double result;
    long long shift;
    unsigned bias;
    unsigned significandbits = bits - expbits - 1; // -1 for sign bit

    if (i == 0) return 0.0;

    // pull the significand
    result = (i&((1LL<<significandbits)-1)); // mask
    result /= (1LL<<significandbits); // convert back to float
    result += 1.0f; // add the one back on

    // deal with the exponent
    bias = (1<<(expbits-1)) - 1;
    shift = ((i>>significandbits)&((1LL<<expbits)-1)) - bias;
    while(shift > 0) { result *= 2.0; shift--; }
    while(shift < 0) { result /= 2.0; shift++; }

    // sign it
    result *= (i>>(bits-1))&1? -1.0: 1.0;

    return result;
}


/*
** packi16() -- store a 16-bit int into a char buffer (like htons())
*/ 
void packi16(unsigned char *buf, unsigned int i, const unsigned char bytodr)
{
    if(bytodr == '<'){
	packi16_little(buf, i);
    } else {
	*buf++ = i>>8; *buf++ = i;
    }
    
}

void packi16_little(unsigned char *buf, unsigned int i)
{
    *buf++ = ((i << 8) >> 8) & 0xFF;
    *buf++ = (i >> 8) & 0xFF;
}

/*
** packi32() -- store a 32-bit int into a char buffer (like htonl())
*/ 
void packi32(unsigned char *buf, unsigned long int i, const unsigned char bytodr)
{
    if(bytodr == '<'){
	packi32_little(buf, i);
    } else {
	*buf++ = i>>24; *buf++ = i>>16;
	*buf++ = i>>8;  *buf++ = i;
    }
}

void packi32_little(unsigned char *buf, unsigned long int i)
{
    *buf++ = ((i<<24)>>24) & 0xFF;
    *buf++ = ((i<<16)>>24) & 0xFF;
    *buf++ = (i<<8)>>24 & 0xFF;
    *buf++ = (i >> 24) & 0xFF;
}

/*
** packi64() -- store a 64-bit int into a char buffer (like htonl())
*/ 
void packi64(unsigned char *buf, unsigned long long int i, const unsigned char bytodr)
{
    if(bytodr == '<'){
	packi64_little(buf, i);
    } else {
	*buf++ = i>>56; *buf++ = i>>48;
	*buf++ = i>>40; *buf++ = i>>32;
	*buf++ = i>>24; *buf++ = i>>16;
	*buf++ = i>>8;  *buf++ = i;
    }
}

void packi64_little(unsigned char *buf, unsigned long long int i)
{
    *buf++ = ((i<<56)>>56) & 0xFF;
    *buf++ = ((i<<48)>>56) & 0xFF;
    *buf++ = ((i<<40)>>56) & 0xFF;
    *buf++ = ((i<<32)>>56) & 0xFF;
    *buf++ = ((i<<24)>>56) & 0xFF;
    *buf++ = ((i<<16)>>56) & 0xFF;
    *buf++ = ((i<<8)>>56) & 0xFF;
    *buf++ = (i >> 56) & 0xFF;
}

/*
** unpacki16() -- unpack a 16-bit int from a char buffer (like ntohs())
*/ 
int unpacki16(const unsigned char *buf, const unsigned char bytodr)
{
    int i;

    if(bytodr == '<'){
	i = unpacki16_little(buf);
    } else {
	i= unpacki16_big(buf);
    }

    return i;
}


int unpacki16_big(const unsigned char *buf)
{
    unsigned int i2 = ((unsigned int)buf[0]<<8) | buf[1];
    int i;

    // change unsigned numbers to signed
    if (i2 <= 0x7fffu) { i = i2; }
    else { i = -1 - (unsigned int)(0xffffu - i2); }

    return i;
}

int unpacki16_little(const unsigned char *buf)
{
    unsigned int i2 = ((unsigned int)buf[1]<<8) | buf[0];
    int i;

    // change unsigned numbers to signed
    if (i2 <= 0x7fffu) { i = i2; }
    else { i = -1 - (unsigned int)(0xffffu - i2); }

    return i;
}


/*
** unpacku16() -- unpack a 16-bit unsigned from a char buffer (like ntohs())
*/ 
unsigned int unpacku16(const unsigned char *buf, const unsigned char bytodr)
{
    unsigned int i;
    if(bytodr == '<'){
	i = unpacku16_little(buf);
    } else {
	i = unpacku16_big(buf);
    }

    return i;
}

unsigned int unpacku16_big(const unsigned char *buf)
{
    return ((unsigned int)buf[0]<<8) | buf[1];
}

unsigned int unpacku16_little(const unsigned char *buf)
{
    return ((unsigned int)buf[1]<<8) | buf[0];
}

/*
** unpacki32() -- unpack a 32-bit int from a char buffer (like ntohl())
*/ 
long int unpacki32(const unsigned char *buf, const unsigned char bytodr)
{
    long int i;

    if(bytodr == '<'){
	i = unpacki32_little(buf);
    } else {
	i = unpacki32_big(buf);
    }

    return i;
}

long int unpacki32_big(const unsigned char *buf)
{
    unsigned long int i2 = ((unsigned long int)buf[0]<<24) |
                           ((unsigned long int)buf[1]<<16) |
                           ((unsigned long int)buf[2]<<8)  |
                           buf[3];
    long int i;

    // change unsigned numbers to signed
    if (i2 <= 0x7fffffffu) { i = i2; }
    else { i = -1 - (long int)(0xffffffffu - i2); }

    return i;
}

long int unpacki32_little(const unsigned char *buf)
{
    unsigned long int i2 = ((unsigned long int)buf[3]<<24) |
                           ((unsigned long int)buf[2]<<16) |
                           ((unsigned long int)buf[1]<<8)  |
                           buf[0];
    long int i;

    // change unsigned numbers to signed
    if (i2 <= 0x7fffffffu) { i = i2; }
    else { i = -1 - (long int)(0xffffffffu - i2); }

    return i;
}


/*
** unpacku32() -- unpack a 32-bit unsigned from a char buffer (like ntohl())
*/ 
unsigned long int unpacku32(const unsigned char *buf, const unsigned char bytodr)
{
    unsigned long int i;

    if(bytodr == '<'){
	i = unpacku32_little(buf);
    } else {
	i = unpacku32_big(buf);
    }

    return i;
}


unsigned long int unpacku32_big(const unsigned char *buf)
{
    return ((unsigned long int)buf[0]<<24) |
           ((unsigned long int)buf[1]<<16) |
           ((unsigned long int)buf[2]<<8)  |
           buf[3];
}

unsigned long int unpacku32_little(const unsigned char *buf)
{
    return ((unsigned long int)buf[3]<<24) |
           ((unsigned long int)buf[2]<<16) |
           ((unsigned long int)buf[1]<<8)  |
           buf[0];
}

/*
** unpacki64() -- unpack a 64-bit int from a char buffer (like ntohl())
*/ 
long long int unpacki64(const unsigned char *buf, const unsigned char bytodr)
{
    unsigned long long int i;

    if(bytodr == '<') {
	i = unpacki64_little(buf);
    } else {
	i = unpacki64_big(buf);
    }

    return i;
}

long long int unpacki64_big(const unsigned char *buf)
{
    unsigned long long int i2;
    long long int i;

    i2 = ((unsigned long long int)buf[0]<<56) |
	((unsigned long long int)buf[1]<<48) |
	((unsigned long long int)buf[2]<<40) |
	((unsigned long long int)buf[3]<<32) |
	((unsigned long long int)buf[4]<<24) |
	((unsigned long long int)buf[5]<<16) |
	((unsigned long long int)buf[6]<<8)  |
	((unsigned long long int)buf[7]);

    // change unsigned numbers to signed
    if (i2 <= 0x7fffffffffffffffu) {
	i = i2;
    } else {
	i = -1 -(long long int)(0xffffffffffffffffu - i2);
    }

    return i;

}


long long int unpacki64_little(const unsigned char *buf)
{
    unsigned long long int i2 = ((unsigned long long int)buf[7]<<56) |
	((unsigned long long int)buf[6]<<48) |
	((unsigned long long int)buf[5]<<40) |
	((unsigned long long int)buf[4]<<32) |
	((unsigned long long int)buf[3]<<24) |
	((unsigned long long int)buf[2]<<16) |
	((unsigned long long int)buf[1]<<8)  |
	((unsigned long long int)buf[0]);
    long long int i;

    // change unsigned numbers to signed
    if (i2 <= 0x7fffffffffffffffu) {
	i = i2;
    } else {
	i = -1 -(long long int)(0xffffffffffffffffu - i2);
    }

    return i;
}


/*
** unpacku64() -- unpack a 64-bit unsigned from a char buffer (like ntohl())
*/ 
unsigned long long int unpacku64(const unsigned char *buf, const unsigned char bytodr)
{
    unsigned long long int i;
    
    if(bytodr == '<') {
	i = unpacku64_little(buf);
    } else {
	i = unpacku64_big(buf);
    }

    return i;
}

long long int unpacku64_little(const unsigned char *buf)
{
    unsigned long long int i = ((unsigned long long int)buf[7]<<56) |
	((unsigned long long int)buf[6]<<48) |
	((unsigned long long int)buf[5]<<40) |
	((unsigned long long int)buf[4]<<32) |
	((unsigned long long int)buf[3]<<24) |
	((unsigned long long int)buf[2]<<16) |
	((unsigned long long int)buf[1]<<8)  |
	((unsigned long long int)buf[0]);

    return i;
}

long long int unpacku64_big(const unsigned char *buf)
{
    unsigned long long int i;

    i =  ((unsigned long long int)buf[0]<<56) |
	((unsigned long long int)buf[1]<<48) |
	((unsigned long long int)buf[2]<<40) |
	((unsigned long long int)buf[3]<<32) |
	((unsigned long long int)buf[4]<<24) |
	((unsigned long long int)buf[5]<<16) |
	((unsigned long long int)buf[6]<<8)  |
	buf[7];

    return i;
}


/*
** pack() -- store data dictated by the format string in the buffer
**
**   bits |byte order          float      alignment
**   -----+------------------------------------------
**      < |   little-endian    standard     none
**      > |   big-endian       standard     none
**
**   bits |signed   unsigned   float   string
**   -----+----------------------------------
**      8 |   c        C         
**     16 |   h        H         f
**     32 |   l        L         d
**     64 |   q        Q         g
**      - |                               s
**
**  (16-bit unsigned length is automatically prepended to strings)
*/ 

unsigned int beej_pack(unsigned char *buf, char *format, ...)
{
    va_list ap;

    signed char c;              // 8-bit
    unsigned char C;

    int h;                      // 16-bit
    unsigned int H;

    long int l;                 // 32-bit
    unsigned long int L;

    long long int q;            // 64-bit
    unsigned long long int Q;

    float f;                    // floats
    double d;
    long double g;
    unsigned long long int fhold;

    char *s;                    // strings
    unsigned int len;

    unsigned int size = 0;

    unsigned char bytodr = NUL_BYT_ORD;

    va_start(ap, format);

    for(; *format != '\0'; format++) {
        switch(*format) {
	case '>': // big-endian
	    bytodr = '>';
	    break;
	    
	case '<': // little-endian
	    bytodr = '<';
	    break;
	    
        case 'c': // 8-bit
            size += 1;
            c = (signed char)va_arg(ap, int); // promoted
            *buf++ = c;
	    bytodr = NUL_BYT_ORD;
            break;

        case 'C': // 8-bit unsigned
            size += 1;
            C = (unsigned char)va_arg(ap, unsigned int); // promoted
            *buf++ = C;
	    bytodr = NUL_BYT_ORD;
            break;

        case 'h': // 16-bit
            size += 2;
            h = va_arg(ap, int);
	    packi16(buf, h, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 2;
            break;

        case 'H': // 16-bit unsigned
            size += 2;
            H = va_arg(ap, unsigned int);
            packi16(buf, H, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 2;
            break;

        case 'l': // 32-bit
            size += 4;
            l = va_arg(ap, long int);
	    packi32(buf, l, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 4;
            break;

        case 'L': // 32-bit unsigned
            size += 4;
            L = va_arg(ap, unsigned long int);
            packi32(buf, L, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 4;
            break;

        case 'q': // 64-bit
            size += 8;
            q = va_arg(ap, long long int);
            packi64(buf, q, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 8;
            break;

        case 'Q': // 64-bit unsigned
            size += 8;
            Q = va_arg(ap, unsigned long long int);
            packi64(buf, Q, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 8;
            break;

        case 'f': // float-16
            size += 2;
            f = (float)va_arg(ap, double); // promoted
            fhold = pack754_16(f); // convert to IEEE 754
            packi16(buf, fhold, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 2;
            break;

        case 'd': // float-32
            size += 4;
            d = va_arg(ap, double);
            fhold = pack754_32(d); // convert to IEEE 754
            packi32(buf, fhold, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 4;
            break;

        case 'g': // float-64
            size += 8;
            g = va_arg(ap, long double);
            fhold = pack754_64(g); // convert to IEEE 754
            packi64(buf, fhold, bytodr);
	    bytodr = NUL_BYT_ORD;
            buf += 8;
            break;

        case 's': // string
            s = va_arg(ap, char*);
            len = strlen(s);
            // size += len + 2;
	    size += len;
            // packi16(buf, len);
            // buf += 2;
            memcpy(buf, s, len);
            buf += len;
            break;
        }
    }

    va_end(ap);

    return size;
}

/*
** unpack() -- unpack data dictated by the format string into the buffer
**
**   bits |byte order          float      alignment
**   -----+------------------------------------------
**      < |   little-endian    standard     none
**      > |   big-endian       standard     none
**
**   bits |signed   unsigned   float   string
**   -----+----------------------------------
**      8 |   c        C         
**     16 |   h        H         f
**     32 |   l        L         d
**     64 |   q        Q         g
**      - |                               s
**
**  (string is extracted based on its stored length, but 's' can be
**  prepended with a max length)
*/
void beej_unpack(const unsigned char *buf, char *format, ...)
{
    va_list ap;

    signed char *c;              // 8-bit
    unsigned char *C;

    int *h;                      // 16-bit
    unsigned int *H;

    long int *l;                 // 32-bit
    unsigned long int *L;

    long long int *q;            // 64-bit
    unsigned long long int *Q;

    float *f;                    // floats
    double *d;
    long double *g;
    unsigned long long int fhold;

    char *s;
    unsigned int len, maxstrlen=0, count;

    unsigned char bytodr = NUL_BYT_ORD;

    va_start(ap, format);

    for(; *format != '\0'; format++) {
        switch(*format) {
	    
	case '>': // big-endian
	    bytodr = '>';
	    break;
	    
	case '<': // little-endian
	    bytodr = '<';
	    break;
	    
        case 'c': // 8-bit
            c = va_arg(ap, signed char*);
            if (*buf <= 0x7f) { *c = *buf;} // re-sign
            else { *c = -1 - (unsigned char)(0xffu - *buf); }
            buf++;
            break;

        case 'C': // 8-bit unsigned
            C = va_arg(ap, unsigned char*);
            *C = *buf++;
            break;

        case 'h': // 16-bit
            h = va_arg(ap, int*);
            *h = unpacki16(buf, bytodr);
            buf += 2;
            break;

        case 'H': // 16-bit unsigned
            H = va_arg(ap, unsigned int*);
            *H = unpacku16(buf, bytodr);
            buf += 2;
            break;

        case 'l': // 32-bit
            l = va_arg(ap, long int*);
            *l = unpacki32(buf, bytodr);
            buf += 4;
            break;

        case 'L': // 32-bit unsigned
            L = va_arg(ap, unsigned long int*);
            *L = unpacku32(buf, bytodr);
            buf += 4;
            break;

        case 'q': // 64-bit
            q = va_arg(ap, long long int*);
            *q = unpacki64(buf, bytodr);
            buf += 8;
            break;

        case 'Q': // 64-bit unsigned
            Q = va_arg(ap, unsigned long long int*);
            *Q = unpacku64(buf, bytodr);
            buf += 8;
            break;

        case 'f': // float
            f = va_arg(ap, float*);
            fhold = unpacku16(buf, bytodr);
            *f = unpack754_16(fhold);
            buf += 2;
            break;

        case 'd': // float-32
            d = va_arg(ap, double*);
            fhold = unpacku32(buf, bytodr);
            *d = unpack754_32(fhold);
            buf += 4;
            break;

        case 'g': // float-64
            g = va_arg(ap, long double*);
            fhold = unpacku64(buf, bytodr);
            *g = unpack754_64(fhold);
            buf += 8;
            break;

        case 's': // string
            s = va_arg(ap, char*);
            len = unpacku16(buf, bytodr);
            buf += 2;
            if (maxstrlen > 0 && len > maxstrlen) count = maxstrlen - 1;
            else count = len;
            memcpy(s, buf, count);
            s[count] = '\0';
            buf += len;
            break;

        default:
            if (isdigit(*format)) { // track max str len
                maxstrlen = maxstrlen * 10 + (*format-'0');
            }
        }

        if (!isdigit(*format)) maxstrlen = 0;
    }

    va_end(ap);
}
