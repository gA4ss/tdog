#ifndef __TDOG_EXCEPT_H
#define __TDOG_EXCEPT_H 1

#include <exception>
#include <string>

#define X_THROW(ExClass, args...)								\
	do															\
		{														\
			ExClass e(args);									\
			e.Init(__FILE__, __PRETTY_FUNCTION__, __LINE__);	\
			throw e;											\
		}														\
	while (false)     
    
#define X_DEFINE_EXCEPTION(ExClass, Base)			\
	ExClass(const std::string& msg = "") throw()	\
	: Base(msg)										\
	{}												\
													\
	~ExClass() throw() {}							\
													\
	/* override */ std::string GetClassName() const	\
	{												\
		return #ExClass;							\
	}
    
class ExceptionBase : public std::exception
{
 public:
	ExceptionBase(const std::string& msg = "") throw();
    
	virtual ~ExceptionBase() throw();
    
	void Init(const char* file, const char* func, int line);
    
	virtual std::string GetClassName() const;
    
	virtual std::string GetMessage() const;
    
	const char* what() const throw();
   
	const std::string& ToString() const;
    
	std::string GetStackTrace() const;
    
 protected:
	std::string mMsg;
	const char* mFile;
	const char* mFunc;
	int mLine;
    
 private:
	enum { MAX_STACK_TRACE_SIZE = 50 };
	void* mStackTrace[MAX_STACK_TRACE_SIZE];
	size_t mStackTraceSize;
	mutable std::string mWhat;
};

/******************************************************************************/
// 异常继承类
/******************************************************************************/

/* 内存溢出 */
class ExceptionOutOfMemory : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionOutOfMemory, ExceptionBase);
};

/* 分配内存失败 */
class ExceptionAllocMemoryFailed : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionAllocMemoryFailed, ExceptionBase);
};

/* 打开文件失败 */
class ExceptionCanNotOpenFile : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionCanNotOpenFile, ExceptionBase);
};

/* 读取文件失败 */
class ExceptionReadFileFailed : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionReadFileFailed, ExceptionBase);
};

/* 写入文件失败 */
class ExceptionWriteFileFailed : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionWriteFileFailed, ExceptionBase);
};

/* IO函数失败 */
class ExceptionIO : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionIO, ExceptionBase);
};

/* 无效ELF格式 */
class ExceptionElfFormatInvalid : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionElfFormatInvalid, ExceptionBase);
};

/* 不能对其进行保护 */
class ExceptionCanNotProtect : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionCanNotProtect, ExceptionBase);
};

/* 加密失败 */
class ExceptionHashFailed : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionHashFailed, ExceptionBase);
};

/* 加密失败 */
class ExceptionEncryptFailed : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionEncryptFailed, ExceptionBase);
};

/* 已经进行过保护 */
class ExceptionAlreadyProtected : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionAlreadyProtected, ExceptionBase);
};

/* 内部异常 */
class ExceptionInternal : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionInternal, ExceptionBase);
};

/* 断言异常 */
class ExceptionAssert : public ExceptionBase
{
 public:
	X_DEFINE_EXCEPTION(ExceptionAssert, ExceptionBase);
};

/******************************************************************************/
// 抛出函数
/******************************************************************************/
void throwOutOfMemory() NORET;
void throwAllocMemoryFailed(const char* msg) NORET;
void throwCanNotOpenFile(const char* msg) NORET;
void throwReadFileFailed(const char* msg) NORET;
void throwWriteFileFailed(const char* msg) NORET;
void throwIO(const char* msg) NORET;
void throwElfFormatInvalid(const char* msg) NORET;
void throwCanNotProtect(const char* msg) NORET;
void throwHashFailed() NORET;
void throwEncryptFailed() NORET;
void throwAlreadyProtected() NORET;
void throwInternal(const char* msg) NORET;
void throwAssert(const char* msg) NORET;

void throwExcept(int e, const char* msg);
/******************************************************************************/
// 异常代码
/******************************************************************************/
enum {
	EXCEPT_HAPPEND = 0x80000000,
	EXCEPT_OUT_OF_MEMORY = 0x80000001,
	EXCEPT_ALLOC_MEMORY_FAILED = 0x80000002,
	EXCEPT_CAN_NOT_OPEN_FILE = 0x80000003,
	EXCEPT_READ_FILE_FAILED = 0x80000004,
	EXCEPT_WRITE_FILE_FAILED = 0x80000005,
	EXCEPT_IO = 0x80000006,
	EXCEPT_ELF_FORMAT_INVALID = 0x80000007,
	EXCEPT_CAN_NOT_PROTECT = 0x80000008,
	EXCEPT_HASH_FAILED = 0x80000009,
	EXCEPT_ENCRYPT_FAILED = 0x8000000A,
	EXCEPT_ALREADY_PROTECTED = 0x8000000B,
	EXCEPT_INTERNAL = 0x8000000C,
	EXCEPT_ASSERT = 0x8000000D
};

#endif
