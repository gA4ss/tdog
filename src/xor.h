#if !defined(__XOR_H__)
#define __XOR_H__

unsigned Xtrlen(unsigned char* ptr);
unsigned MapAscii(char* str);
void RMapAscii(unsigned char* str, unsigned len);
unsigned PolyXorKey(unsigned dwKey);
void XorArray(unsigned dwKey, unsigned char* pPoint, 
			  unsigned char* pOut, unsigned iLength);
void XorArray2(unsigned dwKey, unsigned char* pPoint, 
			   unsigned char* pOut, unsigned iLength);
unsigned XEncrypt(unsigned dwKey, unsigned char* pPoint, unsigned char* pOut);
unsigned XDecrypt(unsigned dwKey, unsigned char* pPoint, unsigned char* pOut);
void XorCoder(unsigned char* pKey, unsigned char* pBuffer, unsigned iLength);
void XorKey32Bits(unsigned dwKeyContext, unsigned char* pKey, 
				  unsigned iKeyLength);

#endif
