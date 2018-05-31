#include "conf.h"

#include <execinfo.h>
#include <stdlib.h>
#include <cxxabi.h>
  
#include <iostream>
#include <sstream>
  
using namespace std;
  
ExceptionBase::ExceptionBase(const std::string& msg) throw()
    : mMsg(msg),
	  mFile("<unknown file>"),
	  mFunc("<unknown func>"),
	  mLine(-1),
	  mStackTraceSize(0)
{}
    
ExceptionBase::~ExceptionBase() throw()
{}

void ExceptionBase::Init(const char* file, const char* func, int line) {
	mFile = file;
	mFunc = func;
	mLine = line;
	mStackTraceSize = backtrace(mStackTrace, MAX_STACK_TRACE_SIZE);
}
    
std::string ExceptionBase::GetClassName() const {
	return "ExceptionBase";
}
    
const char* ExceptionBase::what() const throw() {
	return ToString().c_str();
}
   
const std::string& ExceptionBase::ToString() const {
	if (mWhat.empty()) {
		stringstream sstr("");
		if (mLine > 0) {
			sstr << mFile << "(" << mLine << ")";
		}
		sstr <<  ": " << GetClassName();
		if (!GetMessage().empty()) {
			sstr << ": " << GetMessage();
		}
		sstr << "\nStack Trace:\n";
		sstr << GetStackTrace();
		mWhat = sstr.str();
	}
	return mWhat;
}
    
std::string ExceptionBase::GetMessage() const {
	return mMsg;
}
    
std::string ExceptionBase::GetStackTrace() const {
	if (mStackTraceSize == 0)
		return "<No stack trace>\n";
	char** strings = backtrace_symbols(mStackTrace, 10);
	if (strings == NULL) // Since this is for debug only thus
		// non-critical, don't throw an exception.
		return "<Unknown error backtrace_symbols returned NULL>\n";
    
	std::string result;
	for (size_t i = 0; i < mStackTraceSize; ++i) {
		std::string mangledName = strings[i];
		std::size_t begin = mangledName.find('(');
		std::size_t end = mangledName.find('+', begin);
		if (begin == std::string::npos || end == std::string::npos) {
			result += mangledName;
			result += '\n';
			continue;
		}
		++begin;
		int status;
		char* s = abi::__cxa_demangle(mangledName.substr(begin, end-begin).c_str(),
									  NULL, 0, &status);
		if (status != 0) {
			result += mangledName;
			result += '\n';
			continue;
		}
		std::string demangledName(s);
		free(s);
		// Ignore ExceptionBaseInit so the top frame is the
		// user's frame where this exception is thrown.
		//
		// Can't just ignore frame#0 because the compiler might
		// inline ExceptionBaseInit.
		result += mangledName.substr(0, begin);
		result += demangledName;
		result += mangledName.substr(end);
		result += '\n';
	}
	free(strings);
	return result;
}

void throwOutOfMemory() {
	X_THROW(ExceptionOutOfMemory, "out of memory");
}

void throwAllocMemoryFailed(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionAllocMemoryFailed, "alloc memory failed");
	else
		X_THROW(ExceptionAllocMemoryFailed, msg);
}

void throwCanNotOpenFile(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionCanNotOpenFile, "can not open file");
	else
		X_THROW(ExceptionCanNotOpenFile, msg);
}

void throwReadFileFailed(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionReadFileFailed, "read file failed");
	else 
		X_THROW(ExceptionReadFileFailed, msg);
}

void throwWriteFileFailed(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionWriteFileFailed, "write file failed");
	else
		X_THROW(ExceptionWriteFileFailed, msg);
}

void throwIO(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionIO, "IO failed");
	else
		X_THROW(ExceptionIO, msg);
}

void throwElfFormatInvalid(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionElfFormatInvalid, "elf format invalid");
	else
		X_THROW(ExceptionElfFormatInvalid, msg);
}

void throwCanNotProtect(const char* msg) {
	X_THROW(ExceptionCanNotProtect, msg);
}

void throwHashFailed() {
	X_THROW(ExceptionHashFailed, "hash failed");
}

void throwEncryptFailed() {
	X_THROW(ExceptionEncryptFailed, "encrypt failed");
}

void throwAlreadyProtected() {
	X_THROW(ExceptionAlreadyProtected, "already protected");
}

void throwInternal(const char *msg) {
	if (msg == NULL)
		X_THROW(ExceptionInternal, "internal error");
	else
		X_THROW(ExceptionInternal, msg);
}

void throwAssert(const char* msg) {
	if (msg == NULL)
		X_THROW(ExceptionAssert, "assert failed");
	else
		X_THROW(ExceptionAssert, msg);
}

void throwExcept(int e, const char* msg) {
	switch (e) {
	case EXCEPT_OUT_OF_MEMORY:
		throwOutOfMemory();
		break;
	case EXCEPT_ALLOC_MEMORY_FAILED:
		throwAllocMemoryFailed(msg);
		break;
	case EXCEPT_CAN_NOT_OPEN_FILE:
		throwCanNotOpenFile(msg);
		break;
	case EXCEPT_READ_FILE_FAILED:
		throwReadFileFailed(msg);
		break;
	case EXCEPT_WRITE_FILE_FAILED:
		throwWriteFileFailed(msg);
		break;
	case EXCEPT_IO:
		throwIO(msg);
		break;
	case EXCEPT_ELF_FORMAT_INVALID:
		throwElfFormatInvalid(msg);
		break;
	case EXCEPT_CAN_NOT_PROTECT:
		throwCanNotProtect(msg);
		break;
	case EXCEPT_HASH_FAILED:
		throwHashFailed();
		break;
	case EXCEPT_ENCRYPT_FAILED:
		throwEncryptFailed();
		break;
	case EXCEPT_ALREADY_PROTECTED:
		throwAlreadyProtected();
		break;
	case EXCEPT_INTERNAL:
		throwInternal(msg);
		break;
	case EXCEPT_ASSERT:
		throwAssert(msg);
		break;
	}
}
