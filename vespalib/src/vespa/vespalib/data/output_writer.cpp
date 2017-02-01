// Copyright 2017 Yahoo Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include <vespa/fastos/fastos.h>
#include "output_writer.h"
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>

namespace vespalib {

char *
OutputWriter::reserve_slow(size_t bytes)
{
    _data = _output.commit(_pos).reserve(std::max(_chunk_size, bytes));
    _pos = 0;
    return _data.data;
}

void
OutputWriter::printf(const char *fmt, ...)
{
    char *p = reserve(256);
    int space = (_data.size - _pos);
    int size;
    va_list ap;
    va_start(ap, fmt);
    size = vsnprintf(p, space, fmt, ap);
    va_end(ap);
    assert(size >= 0);
    if (size >= space) {
        space = size + 1;
        p = reserve(space);
        va_start(ap, fmt);
        size = vsnprintf(p, space, fmt, ap);
        va_end(ap);
        assert((size + 1) == space);
    }
    commit(size);
}

} // namespace vespalib
