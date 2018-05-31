#ifndef __TDOG_FILE_H
#define __TDOG_FILE_H 1

class MemBuffer;

class File {
protected:
    File() { }
    virtual ~File() { }
public:
    static void chmod(const char *name, int mode);
    static void rename(const char *old_, const char *new_);
    static void unlink(const char *name);
	/* 2014.4.27 devilogic添加 */
	static void chown(const char* name, int uid, int gid);
};


class FileBase : public File {
protected:
    FileBase();
    virtual ~FileBase();
public:
    virtual bool close();
    virtual void closex();
    virtual bool isOpen() const { return _fd >= 0; }
    int getFd() const { return _fd; }
    const char *getName() const { return _name; }
    virtual off_t st_size() const;  // { return _length; }
    virtual void set_extent(off_t offset, off_t length);

	/* 2014.4.27添加 devilogic */
	virtual void set_params(const char* name,
							int flags,
							int shflags,
							int mode);

	/* 2014.4.27 devilogic 修改属性,原来是protected */
    bool do_sopen();
protected:
    virtual int read(void *buf, int len);
    virtual int readx(void *buf, int len);
    virtual void write(const void *buf, int len);
    virtual void seek(off_t off, int whence);
    virtual off_t tell() const;

    int _fd;
    int _flags;
    int _shflags;
    int _mode;
    const char *_name;
    off_t _offset;
    off_t _length;
public:
    struct stat st;
};


/*************************************************************************
//
**************************************************************************/

class InputFile : public FileBase
{
    typedef FileBase super;
public:
    InputFile();
    virtual ~InputFile();

    virtual void sopen(const char *name, int flags, int shflags);
    virtual void open(const char *name, int flags)
    {
        sopen(name, flags, -1);
    }

    virtual int read(void *buf, int len);
    virtual int readx(void *buf, int len);
    virtual int read(MemBuffer *buf, int len);
    virtual int readx(MemBuffer *buf, int len);
    virtual int read(MemBuffer &buf, int len);
    virtual int readx(MemBuffer &buf, int len);

    virtual void seek(off_t off, int whence);
    virtual off_t tell() const;	
};


/*************************************************************************
//
**************************************************************************/

class OutputFile : public FileBase
{
    typedef FileBase super;
public:
    OutputFile();
    virtual ~OutputFile();

    virtual void sopen(const char *name, int flags, int shflags, int mode);
    virtual void open(const char *name, int flags, int mode)
    {
        sopen(name, flags, -1, mode);
    }
    virtual bool openStdout(int flags=0, bool force=false);

    virtual void write(const void *buf, int len);
    virtual void write(const MemBuffer *buf, int len);
    virtual void write(const MemBuffer &buf, int len);
    virtual void set_extent(off_t offset, off_t length);
    virtual off_t unset_extent();  // returns actual length

    off_t getBytesWritten() const { return bytes_written; }
    virtual off_t st_size() const;  // { return _length; }

    // FIXME - these won't work when using the '--stdout' option
    virtual void seek(off_t off, int whence);
    virtual void rewrite(const void *buf, int len);
    virtual int read(void *buf, int len);
    virtual int readx(void *buf, int len);
	virtual off_t tell() const;

    // util
    static void dump(const char *name, const void *buf, int len, int flags=-1);

protected:
    off_t bytes_written;
};


/*************************************************************************
//
**************************************************************************/

#if 0 /* NOT USED */
class MemoryOutputFile : public FileBase
{
    typedef FileBase super;
public:
    MemoryOutputFile();
    virtual ~MemoryOutputFile() { b = NULL; }

    virtual bool close() { b = NULL; return true; }
    virtual bool isOpen() const { return b != NULL; }
    virtual void open(void *buf, unsigned size)
        { b = (unsigned char*) buf; b_size = size; }

    virtual void write(const void *buf, int len);

    off_t getBytesWritten() const { return bytes_written; }

protected:
    unsigned char* b;
    unsigned b_size;
    unsigned b_pos;
    off_t bytes_written;
};
#endif /* if 0 */


/* 一些辅助工具函数 */
int open_file(const char* iname, FileBase* fi, bool new_file = false);
int open_file(const char* iname, int flags, int shflags, int mode, 
			  FileBase* fi, bool new_file = false);
int copy_file_attribute(const char* name);
#if (USE_FTIME)
int get_file_time(int fd, struct ftime* fi_ftime);
int get_file_time(FileBase* fi, struct ftime* fi_ftime);

int set_file_time(int fd, struct ftime* fi_ftime);
int set_file_time(FileBase* fi, struct ftime* fi_ftime);
#endif

#endif
