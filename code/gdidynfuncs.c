#define DECLARE_GDIPLUS_FUNC(funcName, moduleBase) Gdiplus::fn##funcName = (Gdiplus::Fn##funcName)fn_utils_get_symbol_by_hash((uint8_t*)moduleBase, funcName##_Hash)

int gdiplus_init()
{
#ifdef FUNCS_GDIPLUS
    HMODULE moduleBase;

    // gdiplus.dll
    moduleBase = fn_LoadLibraryA("gdiplus.dll");
    if (moduleBase == NULL) {
        DbgMsg("Can't get base of gdiplus.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
    DbgMsg("gdiplus.dll module base = %08x", moduleBase);
#ifdef fn_GdiplusStartup
    DECLARE_GDIPLUS_FUNC(GdiplusStartup, moduleBase);
#endif
#ifdef fn_GdiplusShutdown
    DECLARE_GDIPLUS_FUNC(GdiplusShutdown, moduleBase);
#endif
#ifdef fn_GdipDeleteBrush
    DECLARE_GDIPLUS_FUNC(GdipDeleteBrush, moduleBase);
#endif
#ifdef fn_GdipFree
    DECLARE_GDIPLUS_FUNC(GdipFree, moduleBase);
#endif
#ifdef fn_GdipCloneBrush
    DECLARE_GDIPLUS_FUNC(GdipCloneBrush, moduleBase);
#endif
#ifdef fn_GdipCreateFontFromLogfontA
    DECLARE_GDIPLUS_FUNC(GdipCreateFontFromLogfontA, moduleBase);
#endif
#ifdef fn_GdipSetStringFormatLineAlign
    DECLARE_GDIPLUS_FUNC(GdipSetStringFormatLineAlign, moduleBase);
#endif
#ifdef fn_GdipSetTextRenderingHint
    DECLARE_GDIPLUS_FUNC(GdipSetTextRenderingHint, moduleBase);
#endif
#ifdef fn_GdipDeleteFont
    DECLARE_GDIPLUS_FUNC(GdipDeleteFont, moduleBase);
#endif
#ifdef fn_GdipDeleteGraphics
    DECLARE_GDIPLUS_FUNC(GdipDeleteGraphics, moduleBase);
#endif
#ifdef fn_GdipSetStringFormatAlign
    DECLARE_GDIPLUS_FUNC(GdipSetStringFormatAlign, moduleBase);
#endif
#ifdef fn_GdipAlloc
    DECLARE_GDIPLUS_FUNC(GdipAlloc, moduleBase);
#endif
#ifdef fn_GdipDrawString
    DECLARE_GDIPLUS_FUNC(GdipDrawString, moduleBase);
#endif
#ifdef fn_GdipCreateFromHDC
    DECLARE_GDIPLUS_FUNC(GdipCreateFromHDC, moduleBase);
#endif
#ifdef fn_GdipCreateLineBrushI
    DECLARE_GDIPLUS_FUNC(GdipCreateLineBrushI, moduleBase);
#endif
#ifdef fn_GdipCreateStringFormat
    DECLARE_GDIPLUS_FUNC(GdipCreateStringFormat, moduleBase);
#endif
#ifdef fn_GdipDeleteStringFormat
    DECLARE_GDIPLUS_FUNC(GdipDeleteStringFormat, moduleBase);
#endif
#ifdef fn_GdipCreateFontFromDC
    DECLARE_GDIPLUS_FUNC(GdipCreateFontFromDC, moduleBase);
#endif

#endif // FUNCS_GDIPLUS
    return 1;
}