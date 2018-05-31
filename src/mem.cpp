#include "globals.h"
#include "mem.h"

static int use_mcheck = -1;

static int mcheck_init() {
    if (use_mcheck < 0)
    {
        use_mcheck = 1;
#if (WITH_VALGRIND) && defined(RUNNING_ON_VALGRIND)
        if (RUNNING_ON_VALGRIND)
        {
            use_mcheck = 0;
        }
#endif
    }
    return use_mcheck;
}


/*************************************************************************
//
**************************************************************************/

MemBuffer::MemBuffer() :
    b(NULL), b_size(0)
{
    if (use_mcheck < 0)
        mcheck_init();
}

MemBuffer::MemBuffer(unsigned size) :
    b(NULL), b_size(0)
{
    alloc(size);
}


MemBuffer::~MemBuffer()
{
    this->dealloc();
}

void MemBuffer::dealloc()
{
    if (b)
    {
        checkState();
		/* 使用内存检查 */
        if (use_mcheck)
        {
			/* 移除标记 */
            set_te32(b - 8, 0);
            set_te32(b - 4, 0);
            set_te32(b + b_size, 0);
            set_te32(b + b_size + 4, 0);
            ::free(b - 16);
        }
        else
            ::free(b);
        b = NULL;
        b_size = 0;
    }
    else
        XASSERT(b_size == 0);
}


void MemBuffer::fill(unsigned off, unsigned len, int value)
{
    checkState();
    XASSERT((int)off >= 0);
    XASSERT((int)len >= 0);
    XASSERT(off <= b_size);
    XASSERT(len <= b_size);
    XASSERT(off + len <= b_size);
    if (len > 0)
        memset(b + off, value, len);
}

/*************************************************************************
//
**************************************************************************/

#define PTR(p)      ((unsigned) (((unsigned)(p)) & 0xffffffff))
#define MAGIC1(p)   (PTR(p) ^ 0xfefdbeeb)
#define MAGIC2(p)   (PTR(p) ^ 0xfefdbeeb ^ 0x80024001)

unsigned MemBuffer::global_alloc_counter = 0;

/* 检查缓冲区是否溢出 */
void MemBuffer::checkState() const
{
    if (!b)
        ERROR_INTERNAL_EXCEPT("block not allocated");
    if (use_mcheck) {
        if (get_te32(b - 4) != MAGIC1(b))
            ERROR_INTERNAL_EXCEPT("memory clobbered before allocated block 1");
        if (get_te32(b - 8) != b_size)
            ERROR_INTERNAL_EXCEPT("memory clobbered before allocated block 2");
        if (get_te32(b + b_size) != MAGIC2(b))
            ERROR_INTERNAL_EXCEPT("memory clobbered past end of allocated block");
    }
    XASSERT((int)b_size > 0);
}

void MemBuffer::alloc(unsigned size)
{
    if (use_mcheck < 0)
        mcheck_init();

    // NOTE: we don't automatically free a used buffer
    XASSERT(b == NULL);
    XASSERT(b_size == 0);
    //
    XASSERT((int)size > 0);
    unsigned total = use_mcheck ? size + 32 : size;
    XASSERT((int)total > 0);
    unsigned char *p = (unsigned char *) malloc(total);
    if (!p)
		ERROR_OUT_OF_MEMORY_EXCEPT(NULL);
	
    b_size = size;
	/* 如果开启内存检查 */
    if (use_mcheck)
    {
        b = p + 16;
        // store magic constants to detect buffer overruns
        set_te32(b - 8, b_size);
        set_te32(b - 4, MAGIC1(b));
        set_te32(b + b_size, MAGIC2(b));
        set_te32(b + b_size + 4, global_alloc_counter++);
    }
    else
        b = p ;

    //fill(0, b_size, (rand() & 0xff) | 1); // debug
}

/* 暂时不支持mcheck */
void MemBuffer::append_alloc(unsigned add_size) {
	unsigned char *tmp = NULL;
	unsigned old_size = 0;

	if ((b_size == 0) || (b == NULL)) {
		alloc(add_size);
		return;
	}

	tmp = (unsigned char *)malloc(b_size);
	if (tmp == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("malloc failed");
		return;
	}

	old_size = b_size;
	memcpy(tmp, b, b_size);
	/* 如果使用了mcheck */
	void *t = NULL;
	unsigned total = 0;
	if (use_mcheck) {
		t = (void*)(((unsigned char*)b) - 16);
		total = b_size + 32;
	} else {
		t = b;
		total = b_size;
	}
	t = realloc(t, total + add_size);

	if (use_mcheck) {
		b = (unsigned char*)t + 16;
	}

	b_size += add_size;

	XASSERT(b);
	XASSERT(b_size > 0);

	memcpy(b, tmp, old_size);
	free(tmp);
}
