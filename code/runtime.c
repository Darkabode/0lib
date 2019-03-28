#include "zmodule.h"
#include "runtime.h"
#include "vector.h"

vector_t _exitFunctions = NULL;

void __stdcall runtime_atexit(FnAtExitCallback fnAtExitCallback)
{
    void** itr;
    void** itrEnd;

    if (_exitFunctions == NULL) {
        _exitFunctions = vector_new();
    }

    itr = vector_begin(_exitFunctions);
    itrEnd = vector_end(_exitFunctions);

    for (; itr != itrEnd; ++itr) {
        if (fnAtExitCallback == (FnAtExitCallback)(*itr)) {
            break;
        }
    }

    if (itr == itrEnd) {
        vector_push_back(_exitFunctions, fnAtExitCallback);
    }
}

void __stdcall runtime_shutdown()
{
    if (_exitFunctions != NULL) {
        void** itr = vector_begin(_exitFunctions);
        void** itrEnd = vector_end(_exitFunctions);

        for (; itr != itrEnd; ++itr) {
            ((FnAtExitCallback)*itr)();
        }

        vector_destroy(_exitFunctions);
    }
}