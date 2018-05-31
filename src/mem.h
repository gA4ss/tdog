#ifndef __TDOG_MEM_H
#define __TDOG_MEM_H 1

class MemBuffer {
public:
    MemBuffer();
    explicit MemBuffer(unsigned size);
    ~MemBuffer();

    void alloc(unsigned size);
	void append_alloc(unsigned add_size);
    void dealloc();
    void checkState() const;
    unsigned getSize() const { return b_size; }

    operator       unsigned char * ()       { return b; }
	void *getVoidPtr()                      { return (void *) b; }
    const void *getVoidPtr() const          { return (const void *) b; }

    void fill(unsigned off, unsigned len, int value);
    void clear(unsigned off, unsigned len)  { fill(off, len, 0); }
    void clear()                            { fill(0, b_size, 0); }

private:
    unsigned char *b;                       /* 内部缓存 */
    unsigned b_size;                        /* 内部缓存长度 */

    static unsigned global_alloc_counter;   /* 全局分配次数 */

    /* 禁止复制与赋值 */
    MemBuffer(const MemBuffer &); // {}
    MemBuffer& operator= (const MemBuffer &); // { return *this; }

    /* 关闭动态分配 */
    DISABLE_NEW_DELETE
};

#endif


