// push fails for very large arrays therefore push
// one item at a time
Array.prototype.extend = function (arr) {
    arr.forEach(function(x) {this.push(x)}, this);
}

function clearMem(addr, len) {
    nullarr = Array();
    for (var i = 0; i < len; i++)
        nullarr.push(0x00);
    Memory.writeByteArray(addr, nullarr);
}

// searches heap chunks of `protection` permissions
// and returns chunks containing the search term as
// an array
function _scanHeap(needle, protection) {
    if (typeof protection === 'undefined')
        protection = 'rw-';
    chunks = Process.enumerateMallocRangesSync(protection);
    found = Array();

    for (var i = 0; i < chunks.length; i++) {
        t = Memory.scanSync(chunks[i]['base'], chunks[i]['size'], needle);
        if (t.length > 0)
            found.extend(t);
    }
    return found;
}

// searches for the needle in the haystack (heap chunks)
// if haystack is not provided, heap chunks of 'rw-'
// permissions are used
// returns array chunks containg the search term
function searchMem(needle, haystack) {
    if (typeof haystack === 'undefined') {
        return _scanHeap(needle);
    }

    found = Array();

    for (var i = 0; i < haystack.length; i++) {
        t = Memory.scanSync(ptr(haystack[i]['address']), haystack[i]['size'], needle);
        if (t.length > 0)
            found.extend(t);
    }
    return found;
}

function readMem(addr, size) {
    return Memory.readByteArray(ptr(addr), size);
}

function writeMem(addr, data) {
    Memory.writeByteArray(ptr(addr), data);
}

function enumerateModules() {
    return Process.enumerateModulesSync();
}

function enumerateRanges(module_name, protection) {
    if (typeof protection === 'undefined')
        protection = 'rw-';
    return Module.enumerateRangesSync(module_name, protection);
}

function ptrSize() {
    return Process.pointerSize;
}

// stuff for drawing with opengl
glColorAddr = Module.findExportByName('OpenGL', 'glColor3f');
glBeginAddr = Module.findExportByName('OpenGL', 'glBegin');
glVertex2fAddr = Module.findExportByName('OpenGL', 'glVertex2f');
glEndAddr = Module.findExportByName('OpenGL', 'glEnd');
glMatrixModeAddr = Module.findExportByName('OpenGL', 'glMatrixMode');
glLoadIdentityAddr = Module.findExportByName('OpenGL', 'glLoadIdentity');
glOrthoAddr = Module.findExportByName('OpenGL', 'glOrtho');
glViewportAddr = Module.findExportByName('OpenGL', 'glViewport');

glBegin = new NativeFunction(glBeginAddr, 'void', ['int']);
glColor3f = new NativeFunction(glColorAddr, 'void', ['float', 'float', 'float']);
glVertex2f = new NativeFunction(glVertex2fAddr, 'void', ['float', 'float']);
glEnd = new NativeFunction(glEndAddr, 'void', []);
glMatrixMode = new NativeFunction(glMatrixModeAddr, 'void', ['int']);
glLoadIdentity = new NativeFunction(glLoadIdentityAddr, 'void', []);
glOrtho = new NativeFunction(glOrthoAddr, 'void', ['double', 'double', 'double', 'double', 'double', 'double']);
glViewport = new NativeFunction(glViewportAddr, 'void', ['int', 'int', 'int', 'int']);


// void TraceLine(vec from, vec to, dynent *pTracer, bool CheckPlayers, traceresult_s *tr, bool SkipTags)
// vec: struct {float x, float y, float z}
// dynent: player pointer
// struct traceresult_s: {
//      vec end;
//      bool collided;
// };
traceLineAsm = Memory.alloc(Process.pageSize);
from = Memory.alloc(4 * 3);
Memory.protect(from, 4 * 3, 'rw-');
to = Memory.alloc(4 * 3);
Memory.protect(to, 4 * 3, 'rw-');
traceresult = Memory.alloc(4 * 3 + 1);
Memory.protect(traceresult, 4 * 3 + 1, 'rw-');
function traceLine(from_x, from_y, from_z, to_x, to_y, to_z, pTracerPtr) {
    // Memory.patchCode changes the permission of traceLineAsm therefore have to
    // reset permission before clearing
    Memory.protect(traceLineAsm, Process.pageSize, 'rwx');
    clearMem(traceLineAsm, Process.pageSize);
    clearMem(from, 4 * 3);
    clearMem(to, 4 * 3);
    clearMem(traceresult, 4 * 3 + 1);

    Memory.writeFloat(from, from_x);
    Memory.writeFloat(from.add(4), from_y);
    Memory.writeFloat(from.add(8), from_z);

    Memory.writeFloat(to, to_x);
    Memory.writeFloat(to.add(4), to_y);
    Memory.writeFloat(to.add(8), to_z);

    Memory.patchCode(traceLineAsm, Process.pageSize, function(code) {
        x86W = new X86Writer(code, { pc: traceLineAsm });
        x86W.putPushReg('xbp');
        x86W.putMovRegReg('xbp', 'xsp');
        x86W.putSubRegImm('xsp', 0x50);
        // x86W.putPushU32(0);
        x86W.putPushU32(traceresult.toInt32());
        x86W.putPushU32(0);
        x86W.putPushU32(pTracerPtr);
        x86W.putPushU32(to_z);
        x86W.putPushU32(to_y);
        x86W.putPushU32(to_x);
        x86W.putPushU32(from_z);
        x86W.putPushU32(from_y);
        x86W.putPushU32(from_x);
        x86W.putCallAddress(ptr(0x12a70));
        x86W.putAddRegImm('xsp', 0x50);
        x86W.putLeave();
        x86W.putRet();
        x86W.flush();
    });
    traceLineNative = new NativeFunction(traceLineAsm, 'void', []);
    traceLineNative();

    Memory.readByteArray(traceresult, 4 * 3);
    return Memory.readByteArray(traceresult.add(4 * 3), 1);
}

function drawBBox(x1, y1, x2, y2) {
    glColor3f(1.0, 0.0, 0.0);
    glViewport(0, 0, 800, 600);
    glMatrixMode(0x1701); // 0x1701 corresponds to GL_PROJECTION
    glLoadIdentity();
    glOrtho(0, 800, 600, 0, 0, 1);
    glBegin(2);
    glVertex2f(x1, y1);
    glVertex2f(x2, y1);
    glVertex2f(x2, y2);
    glVertex2f(x1, y2);
    glEnd();
}

swapBuffersAddr = Module.findExportByName('SDL', 'SDL_GL_SwapBuffers');
swapBuffers = new NativeFunction(swapBuffersAddr, 'void', []);

espStatus = false;
f = undefined;
rectArray = [];

function getRect(rect) {
    return [
        [
            rect.x1,
            rect.y1
        ],
        [
            rect.x2 - rect.x1,
            rect.y2 - rect.y1
        ]
    ];
}

// MyView = ObjC.registerClass({
//     name: 'MyView',
//     super: ObjC.classes.NSView,
//     methods: {
//         '- init': function() {
//             const self = this.super.init()
//             if (self !== null) {
//                 self.setFlipped_(1);
//             }
//         },
//         '- drawRect:': function(rect) {
//             path = ObjC.classes.NSBezierPath.bezierPath();
//             // path = ObjC.classes.NSBezierPath.alloc();
//             // path.init();
//             path.setLineWidth_(3.0);
//             red = ObjC.classes.NSColor.redColor();
//             red.set();
//             for (var i = 0; i < rectArray.length; i++) {
//                 rect = rectArray[i];
//                 path.appendBezierPathWithRect_(getRect(rect));
//             }
//             path.stroke();
//             rectArray = Array();
//         }
//     }
// });

win = undefined;
currentView = undefined;
myView = undefined;
function testDraw() {
    nsApp = ObjC.classes.NSApplication.sharedApplication();
    win = nsApp.windows().objectAtIndex_(0);
    myView = ObjC.classes.MyView.alloc();
    myView.init();
    myView.setWantsLayer_(1);
    wRect = win.frame();
    contentView = win.contentView();
    cRect = contentView.frame();
    rect = [
        wRect[0],
        cRect[1]
    ];
    overlayWin = ObjC.classes.NSWindow.alloc();
    overlayWin.initWithContentRect_styleMask_backing_defer_(rect, 0, 2, 0);
    red = ObjC.classes.NSColor.clearColor();
    overlayWin.setBackgroundColor_(red);
    overlayWin.setOpaque_(0);
    overlayWin.setAlphaValue_(1.0);
    win.addChildWindow_ordered_(overlayWin, 1);
    overlayWin.setValue_forKey_(myView, 'contentView');
}

function drawEsp() {
    ObjC.schedule(ObjC.mainQueue, function() {
        myView.setNeedsDisplay_(1);
    });
}

function addRect(rect) {
    rectArray.push(rect);
}

// function toggleEsp() {
//     if (espStatus) {
//         Interceptor.revert(swapBuffersAddr);
//         espStatus = false;
//     }
//     else {
//         Interceptor.replace(swapBuffersAddr, new NativeCallback(function() {
//             for (var i = 0; i < rectArray.length; i++) {
//                 rect = rectArray[i];
//                 drawBBox(rect.x1, rect.y1, rect.x2, rect.y2);
//             }
//             swapBuffers();
//             rectArray = Array();
//         }, 'void', []));
//         espStatus = true;
//     }
//     return espStatus;
// }

function toggleEsp() {
    // nopIf();
    if (espStatus) {
        if (typeof f !== 'undefined')
            f.detach();
        espStatus = false;
    }
    else {
        // 0x5e054, 0x5dd56, 0x831c4
        f = Interceptor.attach(ptr(0x831c4), function(args) {
            for (var i = 0; i < rectArray.length; i++) {
                rect = rectArray[i];
                drawBBox(rect.x1, rect.y1, rect.x2, rect.y2);
            }
            // swapBuffers();
            rectArray = Array();
        });
        espStatus = true;
    }
    return espStatus;
}

function nopIf() {
    ac = Process.findModuleByName('assaultcube')
    nops = Array();
    for (var i = 0; i < 22; i++)
        nops.push(0x90);
    gl_drawscreen_if_addr = 0x5dfe9;
    Memory.protect(ptr(gl_drawscreen_if_addr), 22, 'rwx');
    Memory.writeByteArray(ptr(gl_drawscreen_if_addr), nops);
    nops = Array();
    for (var i = 0; i < 17; i++)
        nops.push(0x90);
    sdl_gl_swapbuffers_if_addr = 0x5e054;
    Memory.protect(ptr(sdl_gl_swapbuffers_if_addr), 12, 'rwx');
    Memory.writeByteArray(ptr(sdl_gl_swapbuffers_if_addr), nops);

    return true;
}

rpc.exports = {
    searchMem: searchMem,
    readMem: readMem,
    writeMem: writeMem,
    enumerateModules: enumerateModules,
    enumerateRanges: enumerateRanges,
    ptrSize: ptrSize,
    addRect: addRect,
    toggleEsp: toggleEsp,
    testDraw: testDraw,
    drawEsp: drawEsp,
    traceLine: traceLine
};

// ObjC.schedule(ObjC.mainQueue, function() {
//     testDraw();
// });
