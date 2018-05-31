#include "globals.h"
#include "file.h"
#include "mem.h"

/*************************************************************************
 //
 **************************************************************************/
void File::chmod(const char *name, int mode)
{
#if (HAVE_CHMOD)
    if (::chmod(name,mode) != 0)
		ERROR_IO_EXCEPT("chmod failed : %s", name);	
#else
    UNUSED(name); UNUSED(mode);
#endif
}


void File::rename(const char *old_, const char *new_) {
	if (::rename(old_,new_) != 0)
		ERROR_IO_EXCEPT("rename failed : %s -> %s", old_, new_);
}


void File::unlink(const char *name) {
    if (::unlink(name) != 0)
		ERROR_IO_EXCEPT("unlink failed : %s", name);
}

/* 2014.4.27 devilogic添加 */
void File::chown(const char* name, int uid, int gid) {
#if (HAVE_CHOWN)
    if (::chown(name,uid,gid) != 0)
		ERROR_IO_EXCEPT("chown failed : %s-%d-%d", name, uid, gid);
#else
    UNUSED(name); UNUSED(uid); UNUSED(gid);
#endif	
}

/*************************************************************************
 //
 **************************************************************************/

FileBase::FileBase() :
    _fd(-1), _flags(0), _shflags(0), _mode(0), _name(NULL), _offset(0), _length(0)
{
    memset(&st,0,sizeof(st));
}


FileBase::~FileBase()
{
    if (isOpen()) {
		DEBUG_INFO("%s is not close: %s\n", _name, __PRETTY_FUNCTION__);
	}

    // FIXME: we should use close() during exception unwinding but
    //        closex() otherwise
    closex();
}


bool FileBase::do_sopen() {
    if (_shflags < 0)
        _fd = ::open(_name, _flags, _mode);
    else {
		//_fd = ::sopen(_name, _flags, _shflags, _mode);
		_fd = ::open(_name, _flags, _mode);
	}
    if (_fd < 0)
        return false;
    if (::fstat(_fd, &st) != 0)
		ERROR_IO_EXCEPT("fstat failed : %s", _name);
    _length = st.st_size;
    return true;
}


bool FileBase::close() {
    bool ok = true;
    if (isOpen() && 
		_fd != STDIN_FILENO && 
		_fd != STDOUT_FILENO && 
		_fd != STDERR_FILENO)
        if (::close(_fd) == -1)
            ok = false;
    _fd = -1;
    _flags = 0;
    _mode = 0;
    _name = NULL;
    _offset = 0;
    _length = 0;
    return ok;
}


void FileBase::closex() {
    if (!close())
		ERROR_INTERNAL_EXCEPT("close failed : %s", _name);
}


int FileBase::read(void *buf, int len) {
    if (!isOpen() || len < 0)
		ERROR_INTERNAL_EXCEPT("bad read file:%s not open or length is 0", _name);
    errno = 0;
    long l = safe_read(_fd, buf, len);
    if (errno)
		ERROR_READ_FILE_FAILED_EXCEPT("read file %s failed", _name);
    return (int) l;
}


int FileBase::readx(void *buf, int len) {
    int l = this->read(buf, len);
    if (l != len)
		ERROR_INTERNAL_EXCEPT("read file %s, read length != file total length, EOF failed", _name);
    return l;
}

void FileBase::write(const void *buf, int len) {
    if (!isOpen() || len < 0)
		ERROR_INTERNAL_EXCEPT("bad write file:%s not open or length is 0", _name);
    errno = 0;
    long l = safe_write(_fd, buf, len);
    if (l != len)
		ERROR_WRITE_FILE_FAILED_EXCEPT("write file %s failed", _name);
}


void FileBase::seek(off_t off, int whence) {
    if (!isOpen())
		ERROR_INTERNAL_EXCEPT("bad seek file : %s not open", _name);
    if (whence == SEEK_SET) {
        if (off < 0)
			ERROR_INTERNAL_EXCEPT("bad seek file : %s, (SEEK_SET)offset < 0", _name);
        off += _offset;
    }
    if (whence == SEEK_END) {
        if (off > 0)
		ERROR_INTERNAL_EXCEPT("bad seek file : %s, (SEEK_END)offset > 0", _name);
        off += _offset + _length;
        whence = SEEK_SET;
    }
    if (::lseek(_fd,off,whence) < 0)
		ERROR_IO_EXCEPT("bad seek file : %s", _name);
}


off_t FileBase::tell() const {
    if (!isOpen())
		ERROR_INTERNAL_EXCEPT("bad tell file : %s not open", _name);
    off_t l = ::lseek(_fd, 0, SEEK_CUR);
    if (l < 0)
		ERROR_IO_EXCEPT("bad tell file : %s", _name);
    return l - _offset;
}


void FileBase::set_extent(off_t offset, off_t length) {
    _offset = offset;
    _length = length;
}

off_t FileBase::st_size() const {
    return _length;
}

/* 2014.4.27添加 devilogic */
void FileBase::set_params(const char* name,
						  int flags,
						  int shflags,
						  int mode) {
	_name = name;
	_flags = flags;
	_shflags = shflags;
	_mode = mode;
	_offset = 0;
	_length = 0;
}

/*************************************************************************
 //
 **************************************************************************/

InputFile::InputFile()
{
}


InputFile::~InputFile()
{
}

void InputFile::sopen(const char *name, int flags, int shflags)
{
    close();
    _name = name;
    _flags = flags;
    _shflags = shflags;
    _mode = 0;
    _offset = 0;
    _length = 0;
    if (!FileBase::do_sopen()) {
		if (errno == ENOENT)
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("open file :%s failed", _name);
		else if (errno == EEXIST)
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("file %s already exist", _name);
		else
			ERROR_INTERNAL_EXCEPT("open file : %s failed", _name);
	}
}


int InputFile::read(void *buf, int len)
{
    return super::read(buf, len);
}

int InputFile::readx(void *buf, int len)
{
    return super::readx(buf, len);
}


int InputFile::read(MemBuffer *buf, int len) {
    buf->checkState();
    XASSERT((unsigned)len <= buf->getSize());
    return read(buf->getVoidPtr(), len);
}

int InputFile::readx(MemBuffer *buf, int len)
{
    buf->checkState();
    XASSERT((unsigned)len <= buf->getSize());
    return read(buf->getVoidPtr(), len);
}


int InputFile::read(MemBuffer &buf, int len)
{
    return read(&buf, len);
}

int InputFile::readx(MemBuffer &buf, int len)
{
    return readx(&buf, len);
}


void InputFile::seek(off_t off, int whence)
{
    super::seek(off,whence);
}


off_t InputFile::tell() const
{
    return super::tell();
}


/*************************************************************************
 //
 **************************************************************************/

OutputFile::OutputFile() :
    bytes_written(0)
{
}


OutputFile::~OutputFile()
{
}


void OutputFile::sopen(const char *name, int flags, int shflags, int mode) {
    close();
    _name = name;
    _flags = flags;
    _shflags = shflags;
    _mode = mode;
    _offset = 0;
    _length = 0;
    if (!FileBase::do_sopen())
		{
#if 0
			// don't throw FileNotFound here -- this is confusing
			if (errno == ENOENT)
				ERROR_CAN_NOT_OPEN_FILE_EXCEPT("file %s not found", _name);
			else
#endif
				if (errno == EEXIST)
					ERROR_CAN_NOT_OPEN_FILE_EXCEPT("file %s already exist", _name);
				else
					ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file %s", _name);
		}
}

bool OutputFile::openStdout(int flags, bool force) {
    close();
    int fd = STDOUT_FILENO;
    if (!force && l_isatty(fd))
        return false;
    _name = "<stdout>";
    _flags = flags;
    _shflags = -1;
    _mode = 0;
    _offset = 0;
    _length = 0;
    if (flags && l_set_binmode(fd, 1) == -1)
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file %s", _name);
    _fd = fd;
    return true;
}


void OutputFile::write(const void *buf, int len) {
    super::write(buf, len);
    bytes_written += len;
}

off_t OutputFile::st_size() const {
    struct stat my_st;
    my_st.st_size = 0;
    if (::fstat(_fd, &my_st) != 0)
        ERROR_IO_EXCEPT("fstat failed : %s", _name);
    return my_st.st_size;
}


void OutputFile::write(const MemBuffer *buf, int len) {
    buf->checkState();
    XASSERT((unsigned)len <= buf->getSize());
    write(buf->getVoidPtr(), len);
}


void OutputFile::write(const MemBuffer &buf, int len) {
    write(&buf, len);
}

void OutputFile::rewrite(const void *buf, int len) {
    write(buf, len);
    bytes_written -= len;       // restore
}

void OutputFile::seek(off_t off, int whence) {
    switch (whence) {
    case SEEK_SET: {
        if (bytes_written < off) {
            bytes_written = off;
        }
        _length = bytes_written;  // cheap, lazy update; needed?
    } break;
    case SEEK_END: {
        _length = bytes_written;  // necessary
    } break;
    }
    super::seek(off,whence);
}

int OutputFile::read(void *buf, int len) {
    InputFile infile;
    infile.open(this->getName(), O_RDONLY);
    infile.seek(this->tell(), SEEK_SET);
    return infile.read(buf, len);
}

int OutputFile::readx(void *buf, int len) {
    InputFile infile;
    infile.open(this->getName(), O_RDONLY);
    infile.seek(this->tell(), SEEK_SET);
    return infile.readx(buf, len);
}

off_t OutputFile::tell() const {
    return super::tell();
}

void OutputFile::set_extent(off_t offset, off_t length) {
    super::set_extent(offset, length);
    bytes_written = 0;
    if (0==offset && (off_t)~0u==length) {
        if (::fstat(_fd, &st) != 0)
            ERROR_IO_EXCEPT("fstat failed : %s", _name);
        _length = st.st_size - offset;
    }
}

off_t OutputFile::unset_extent() {
    off_t l = ::lseek(_fd, 0, SEEK_END);
    if (l < 0)
		ERROR_IO_EXCEPT("seek failed : %s", _name);
    _offset = 0;
    _length = l;
    bytes_written = _length;
    return _length;
}

void OutputFile::dump(const char *name, const void *buf, int len, int flags) {
    if (flags < 0)
		flags = O_CREAT | O_BINARY | O_TRUNC;
    flags |= O_WRONLY;
    OutputFile f;
    f.open(name, flags, 0600);
    f.write(buf, len);
    f.closex();
}


/*************************************************************************
 //
 **************************************************************************/

#if 0

MemoryOutputFile::MemoryOutputFile() :
    b(NULL), b_size(0), b_pos(0), bytes_written(0)
{
}


void MemoryOutputFile::write(const void *buf, int len)
{
    if (!isOpen() || len < 0)
        ERROR_INTERNAL_EXCEPT("bad write memory not open or length is 0");
    if (len == 0)
        return;
    if (b_pos + len > b_size)
		ERROR_OUT_OF_MEMORY_EXCEPT();
    memcpy(b + b_pos, buf, len);
    b_pos += len;
    bytes_written += len;
}


#endif /* if 0 */

#if !defined(SH_DENYRW)
#  define SH_DENYRW     (-1)
#endif
#if !defined(SH_DENYWR)
#  define SH_DENYWR     (-1)
#endif

int open_file(const char* iname, FileBase* fi, bool new_file) {
	int ret = open_file(iname, O_RDONLY | O_BINARY, SH_DENYWR, 0, 
						fi, new_file);
	return ret;
}

int open_file(const char* iname, int flags, int shflags, int mode, 
			  FileBase* fi, bool new_file) {
	int r;
    struct stat st;

	XASSERT(iname);
	XASSERT(fi);

	if (new_file == false) {

		/* 获取输入文件状态 */
		memset(&st, 0, sizeof(st));
#if (HAVE_LSTAT)
		r = lstat(iname,&st);
#else
		r = stat(iname,&st);
#endif

		if (r != 0)
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("file %s not found", iname);
		if (!(S_ISREG(st.st_mode)))
			ERROR_INTERNAL_EXCEPT("not a regular file");
#if defined(__unix__)
		/* 权限不足 */
		if ((st.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0)
			ERROR_INTERNAL_EXCEPT("file has special permissions");
#endif
		/* 空文件 */
		if (st.st_size <= 0)
			ERROR_INTERNAL_EXCEPT("empty file");

		/* 文件过大 */
		if (st.st_size >= 1024*1024*1024)
			ERROR_INTERNAL_EXCEPT("file is too large");

		/* 文件不可写 */
		if ((st.st_mode & S_IWUSR) == 0) {
			bool skip = true;
			if (skip)
				ERROR_INTERNAL_EXCEPT("file is write protected");
		}

		/* 打开输入文件 */
		fi->st = st;
	}

	/* 这里真正执行打开操作 */
	fi->close();
	fi->set_params(iname, flags, shflags, mode);
    if (!fi->do_sopen()) {
		if (errno == EEXIST)
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("file %s already exist", iname);
		else
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file %s", iname);
    }

	return 0;	
}

int copy_file_attribute(const char* name) {
	InputFile fi;
	int r = open_file(name, &fi);
	struct stat* st = &fi.st;
	struct utimbuf u;
	u.actime = st->st_atime;
	u.modtime = st->st_mtime;
	r = utime(name, &u);

	File::chmod(name, st->st_mode);	               /* 权限 */
	File::chown(name, st->st_uid, st->st_gid);     /* 属组 */
	
	fi.close();
	return r;
}

#if (USE_FTIME)
int get_file_time(int fd, struct ftime* fi_ftime) {
	XASSERT(fd);
	XASSERT(fi_ftime);

    memset(fi_ftime, 0, sizeof(*fi_ftime));
	if (getftime(fd, fi_ftime) != 0)
		ERROR_IO_EXCEPT("cannot determine file timestamp");
	return 0;
}

int get_file_time(FileBase* fi, struct ftime* fi_ftime) {
	int ret = get_file_time(fi->getFd(), fi_ftime);
	return ret;
}

int set_file_time(int fd, struct ftime* fi_ftime) {
	XASSERT(fi);
	XASSERT(fi_ftime);

	int r;
#if (USE__FUTIME)
	struct _utimbuf u;
	u.actime = fi->st.st_atime;
	u.modtime = fi->st.st_mtime;
	r = _futime(fd, &u);
#else
	r = setftime(fd, fi_ftime);
#endif
	return r;
}

int set_file_time(FileBase* fi, struct ftime* fi_ftime) {
	int r = set_file_time(fi->getFd(), fi_ftime);
	return r;
}

#endif
