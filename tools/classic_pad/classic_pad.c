/*
 * Classic Controller / GameCube controller support for My Pokémon Ranch
 * (Platinum, WBME main DOL).
 *
 * The game samples every controller from one OSAlarm handler at 30 Hz
 * (0x8038C3E0).  For each Wii Remote channel it calls
 *
 *     KPADRead(chan, &ring[slot][chan], 1)          @ 0x8038C434
 *
 * and everything else in the game -- per-player state, the HOME Menu, the
 * pointer, the Nunchuk stick -- is derived from that KPADStatus.  The same
 * handler also calls PADRead() into its own ring, but nothing reads the
 * GameCube data back (the only getter call, 0x80170AD8, discards it).
 *
 * appl.py redirects the `bl KPADRead` above to cp_kpad_read() below, which
 * calls the real KPADRead and then rewrites the status so that a Classic
 * Controller (attached to the Wii Remote) or a GameCube controller (in the
 * port with the same number) looks like a Wii Remote + Nunchuk:
 *
 *   left stick / control stick   -> pointer (virtual cursor)
 *   right stick / C-stick        -> Nunchuk stick (viewing angle)
 *   buttons                      -> remapped onto Wii Remote / Nunchuk bits
 *
 * A GameCube controller works with no Wii Remote connected at all: the
 * status is synthesised as a connected Remote + Nunchuk.  So that Dolphin's
 * default "Standard Controller in port 1" can't hijack a Wii Remote player,
 * a GameCube controller only takes part once it has actually been used, and
 * pointing a real Wii Remote takes the pointer back from the stick.
 *
 * Runs in the alarm handler, so: no OS calls, no allocation, keep it short.
 * The code does not fit in any one free gap of Text 0, so each function and
 * table is pinned to a gap by section name (letters = gaps in classic_pad.ld);
 * build.sh packs the pieces into classic_pad.bin as address-tagged records
 * for appl.py.
 */

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef float f32;

typedef struct { f32 x, y; } Vec2;
typedef struct { f32 x, y, z; } Vec;

/* RVL SDK KPADStatus, 0x84 bytes (this game's KPAD revision). */
typedef struct {
    u32 hold, trig, release;            /* 0x00 */
    Vec acc;                            /* 0x0C */
    f32 acc_value, acc_speed;           /* 0x18 */
    Vec2 pos, vec;                      /* 0x20 */
    f32 speed;                          /* 0x30 */
    Vec2 horizon, hori_vec;             /* 0x34 */
    f32 hori_speed;                     /* 0x44 */
    f32 dist, dist_vec, dist_speed;     /* 0x48 */
    Vec2 acc_vertical;                  /* 0x54 */
    u8 dev_type;                        /* 0x5C */
    s8 wpad_err;                        /* 0x5D */
    s8 dpd_valid_fg;                    /* 0x5E */
    u8 data_format;                     /* 0x5F */
    union {                             /* 0x60 */
        struct { Vec2 stick; Vec acc; f32 acc_value, acc_speed; } fs;
        struct {
            u32 hold, trig, release;
            Vec2 lstick, rstick;
            f32 ltrigger, rtrigger;
        } cl;
    } ex;
} KPADStatus;

/* RVL SDK PADStatus, 12 bytes. */
typedef struct {
    u16 button;
    s8 stickX, stickY, substickX, substickY;
    u8 triggerL, triggerR, analogA, analogB;
    s8 err;
} PADStatus;

typedef char kpad_size_check[(sizeof(KPADStatus) == 0x84) ? 1 : -1];
typedef char pad_size_check[(sizeof(PADStatus) == 12) ? 1 : -1];

/* ---- game / SDK addresses (WBME main DOL) ------------------------------ */

#define KPADRead ((s32 (*)(s32, KPADStatus *, u32))0x80586910)

/* Pad manager object, r13-0x1280.  +0x30 = ring write index (0..59);
 * PADStatus ring at +0x86C8, 60 slots x 4 ports x 12 bytes. */
#define PAD_MGR          (*(u8 *volatile *)0x807C1820)
#define PAD_RING_WIDX    0x30
#define PAD_RING_OFFSET  0x86C8
#define PAD_RING_SLOTS   60
#define PAD_RING_STRIDE  48

/* KPAD's per-channel "pointer wanted" flag (inside_kpads[chan] + 0x520).
 * KPADInit sets it to 1; the game clears it with its DPD-off request. */
#define KPAD_DPD_ON(ch)  (*(volatile u8 *)(0x80780720 + (ch) * 0x538))

/* ---- SDK constants ----------------------------------------------------- */

#define WPAD_DEV_FREESTYLE      1
#define WPAD_DEV_CLASSIC        2
#define WPAD_FMT_FS_ACC         4
#define WPAD_FMT_FS_ACC_DPD     5

#define PAD_ERR_NONE            0
#define PAD_ERR_NO_CONTROLLER  (-1)

/* Wii Remote (+ Nunchuk) bits as KPAD reports them in `hold`. */
#define RM_LEFT   0x0001
#define RM_RIGHT  0x0002
#define RM_DOWN   0x0004
#define RM_UP     0x0008
#define RM_PLUS   0x0010
#define RM_2      0x0100
#define RM_1      0x0200
#define RM_B      0x0400
#define RM_A      0x0800
#define RM_MINUS  0x1000
#define RM_Z      0x2000
#define RM_C      0x4000
#define RM_HOME   0x8000

/* Classic Controller bits (KPADStatus.ex.cl.hold). */
#define CL_UP     0x0001
#define CL_LEFT   0x0002
#define CL_ZR     0x0004
#define CL_X      0x0008
#define CL_A      0x0010
#define CL_Y      0x0020
#define CL_B      0x0040
#define CL_ZL     0x0080
#define CL_R      0x0200
#define CL_PLUS   0x0400
#define CL_HOME   0x0800
#define CL_MINUS  0x1000
#define CL_L      0x2000
#define CL_DOWN   0x4000
#define CL_RIGHT  0x8000

/* GameCube controller bits (PADStatus.button). */
#define GC_LEFT   0x0001
#define GC_RIGHT  0x0002
#define GC_DOWN   0x0004
#define GC_UP     0x0008
#define GC_Z      0x0010
#define GC_R      0x0020
#define GC_L      0x0040
#define GC_A      0x0100
#define GC_B      0x0200
#define GC_X      0x0400
#define GC_Y      0x0800
#define GC_START  0x1000

/* ---- placement (see classic_pad.ld) ------------------------------------ */

#define IN_GAP(g) __attribute__((section(".cp." #g), noinline))
#define RODATA_GAP(g) __attribute__((section(".cp." #g ".ro")))
#define DATA_GAP(g) __attribute__((section(".cp." #g ".rw")))

/* ---- tuning ------------------------------------------------------------- */

typedef struct {
    f32 deadzone2;      /* squared stick radius ignored */
    f32 speed_x;        /* pointer units per 1/30 s at full tilt */
    f32 speed_y;
    f32 min_gain;       /* fraction of full speed just past the deadzone */
    f32 limit_x;        /* the game's own pointer clamp (0x8038D784) */
    f32 limit_y;
    f32 wake2;          /* squared real-pointer move that takes it back */
    f32 gc_range;       /* PADClamp'ed control stick: axis max 57 */
    f32 gc_crange;      /* PADClamp'ed C-stick: axis max 44 */
    f32 rest_dist;      /* KPAD dist reported for a synthesised remote */
    f32 oct;            /* sqrt(2)-1, octagonal |v| approximation */
    f32 zero, one, neg_one;
} Tuning;

static const Tuning k_tune RODATA_GAP(e) = {
    0.15f * 0.15f,
    0.070f,
    0.090f,
    0.25f,
    0.8888889f,
    0.9285714f,
    0.03f * 0.03f,
    50.0f,
    40.0f,
    1.5f,
    0.4142136f,
    0.0f, 1.0f, -1.0f,
};

#define GC_TRIGGER_PRESS  100   /* analog L/R (0-150 after PADClamp) */

/* ---- per-channel state --------------------------------------------------- */

typedef struct {
    Vec2 cursor;        /* virtual pointer */
    Vec2 last_real;     /* last real DPD position seen */
    u32 prev_hold;      /* hold reported last sample */
    u8 virt;            /* 1: pointer comes from the stick */
    u8 gc_used;         /* GameCube controller in this port has been used */
    u8 pad[2];
} ChanState;

static ChanState g_state[4] DATA_GAP(g) = {
    { {0.0f, 0.0f}, {0.0f, 0.0f}, 0, 0, 0, {0, 0} },
    { {0.0f, 0.0f}, {0.0f, 0.0f}, 0, 0, 0, {0, 0} },
    { {0.0f, 0.0f}, {0.0f, 0.0f}, 0, 0, 0, {0, 0} },
    { {0.0f, 0.0f}, {0.0f, 0.0f}, 0, 0, 0, {0, 0} },
};

/* Button remap tables: {source bits, Wii Remote bits}, zero-terminated. */
static const u16 k_map_classic[][2] RODATA_GAP(f) = {
    { CL_UP,    RM_UP    },
    { CL_DOWN,  RM_DOWN  },
    { CL_LEFT,  RM_LEFT  },
    { CL_RIGHT, RM_RIGHT },
    { CL_A,     RM_A     },
    { CL_B,     RM_B     },
    { CL_X,     RM_2     },
    { CL_Y,     RM_1     },
    { CL_PLUS  | CL_R, RM_PLUS  },
    { CL_MINUS | CL_L, RM_MINUS },
    { CL_HOME,  RM_HOME  },
    { CL_ZR,    RM_Z     },
    { CL_ZL,    RM_C     },
    { 0, 0 },
};

/* GC_L / GC_R also cover the analog triggers, see cp_gc_poll(). */
static const u16 k_map_gamecube[][2] RODATA_GAP(f) = {
    { GC_UP,    RM_UP    },
    { GC_DOWN,  RM_DOWN  },
    { GC_LEFT,  RM_LEFT  },
    { GC_RIGHT, RM_RIGHT },
    { GC_A,     RM_A     },
    { GC_B,     RM_B     },
    { GC_X,     RM_2     },
    { GC_Y,     RM_1     },
    { GC_Z,     RM_Z     },
    { GC_START, RM_HOME  },
    { GC_R,     RM_PLUS  },
    { GC_L,     RM_MINUS },
    { 0, 0 },
};

/* Hide the tuning block's contents from the optimiser so every constant is
 * one lfs off a base register instead of a lis/lfs pair. */
static inline const Tuning *tune(void)
{
    const Tuning *t = &k_tune;
    __asm__("" : "+r"(t));
    return t;
}

/* ---- helpers -------------------------------------------------------------- */

static inline f32 fabs_(f32 v) { return v < 0.0f ? -v : v; }

static inline f32 mag2(f32 x, f32 y) { return x * x + y * y; }

IN_GAP(c) f32 cp_clamp(f32 v, f32 lim)
{
    if (v > lim) return lim;
    if (v < -lim) return -lim;
    return v;
}

IN_GAP(c) u32 cp_remap(u32 b, const u16 (*t)[2])
{
    u32 r = 0;
    for (; t[0][0]; t++)
        if (b & t[0][0])
            r |= t[0][1];
    return r;
}

/* GameCube stick axis (s8, already PADClamp'ed) to [-1, 1]. */
IN_GAP(b) f32 cp_gc_axis(s32 v, f32 range)
{
    return cp_clamp((f32)v / range, 1.0f);
}

/* Prefer whichever stick is pushed further. */
IN_GAP(d) void cp_stick_merge(Vec2 *dst, const Vec2 *src)
{
    if (mag2(src->x, src->y) > mag2(dst->x, dst->y))
        *dst = *src;
}

/* ---- GameCube controller ------------------------------------------------- */

typedef struct {
    u32 hold;           /* mapped to Wii Remote bits */
    Vec2 ptr, cam;      /* control stick, C-stick in [-1, 1] */
} GcInput;

/* Returns 1 if the GameCube controller in `port` takes part this sample.
 * The handler reads KPAD for ring slot w before PADRead fills slot w, so
 * the newest GameCube sample is in slot w-1. */
IN_GAP(a) int cp_gc_poll(s32 port, ChanState *st, GcInput *in)
{
    const Tuning *t = tune();
    const PADStatus *p;
    u8 *mgr = PAD_MGR;
    s32 w;
    u32 b;

    /* Every exit below may report the pad as taking part, so start idle. */
    in->hold = 0;
    in->ptr.x = in->ptr.y = in->cam.x = in->cam.y = t->zero;

    if (!mgr)
        return 0;
    w = *(s32 *)(mgr + PAD_RING_WIDX);
    if ((u32)w >= PAD_RING_SLOTS)
        return 0;
    w = (w == 0) ? PAD_RING_SLOTS - 1 : w - 1;
    p = (const PADStatus *)(mgr + PAD_RING_OFFSET + w * PAD_RING_STRIDE
                            + port * (s32)sizeof(PADStatus));

    if (p->err == PAD_ERR_NO_CONTROLLER) {
        st->gc_used = 0;
        return 0;
    }
    if (p->err != PAD_ERR_NONE)
        return st->gc_used;          /* transient error: no input this tick */

    b = p->button;
    if (p->triggerR >= GC_TRIGGER_PRESS) b |= GC_R;
    if (p->triggerL >= GC_TRIGGER_PRESS) b |= GC_L;
    in->hold = cp_remap(b, k_map_gamecube);
    in->ptr.x = cp_gc_axis(p->stickX, t->gc_range);
    in->ptr.y = cp_gc_axis(p->stickY, t->gc_range);
    in->cam.x = cp_gc_axis(p->substickX, t->gc_crange);
    in->cam.y = cp_gc_axis(p->substickY, t->gc_crange);

    if (in->hold || mag2(in->ptr.x, in->ptr.y) > t->deadzone2
                 || mag2(in->cam.x, in->cam.y) > t->deadzone2)
        st->gc_used = 1;
    return st->gc_used;
}

/* ---- pointer ------------------------------------------------------------- */

/* Report the virtual cursor as the pointer.  `old` is last sample's. */
IN_GAP(c) void cp_pointer_out(KPADStatus *s, const ChanState *st, s32 chan,
                              const Vec2 *old)
{
    const Tuning *t = tune();
    f32 ax, ay;

    s->pos = st->cursor;
    s->vec.x = st->cursor.x - old->x;
    s->vec.y = st->cursor.y - old->y;
    ax = fabs_(s->vec.x);
    ay = fabs_(s->vec.y);
    /* octagonal approximation of |vec| (Broadway has no fsqrt) */
    s->speed = (ax > ay) ? ax + t->oct * ay : ay + t->oct * ax;
    s->horizon.x = t->one;
    s->horizon.y = s->hori_vec.x = s->hori_vec.y = s->hori_speed
                 = s->dist_vec = s->dist_speed = t->zero;
    if (s->dist <= t->zero)
        s->dist = t->rest_dist;
    s->dpd_valid_fg = KPAD_DPD_ON(chan) ? 2 : 0;
}

/* `real_ok`: a Wii Remote is connected, pointed at the screen and is the
 * pointing device (not just a Classic Controller's host). */
IN_GAP(b) void cp_pointer(KPADStatus *s, ChanState *st, s32 chan,
                          const Vec2 *stick, int real_ok)
{
    const Tuning *t = tune();
    Vec2 old;
    f32 m2, dx, dy;

    if (real_ok) {
        dx = s->pos.x - st->last_real.x;
        dy = s->pos.y - st->last_real.y;
        st->last_real = s->pos;
        if (!st->virt || mag2(dx, dy) > t->wake2) {
            /* The Wii Remote is being pointed: let it drive. */
            st->virt = 0;
            st->cursor = s->pos;
        }
    } else {
        st->virt = 1;
    }
    old = st->cursor;

    m2 = mag2(stick->x, stick->y);
    if (m2 > t->deadzone2) {
        f32 gain;
        if (m2 > t->one)            /* square-gated sticks on a diagonal */
            m2 = t->one;
        gain = t->min_gain + (t->one - t->min_gain) * m2;
        st->virt = 1;
        st->cursor.x = cp_clamp(old.x + stick->x * gain * t->speed_x, t->limit_x);
        /* screen y grows downwards, stick y grows upwards */
        st->cursor.y = cp_clamp(old.y - stick->y * gain * t->speed_y, t->limit_y);
    }

    if (st->virt)
        cp_pointer_out(s, st, chan, &old);
    s->data_format = KPAD_DPD_ON(chan) ? WPAD_FMT_FS_ACC_DPD : WPAD_FMT_FS_ACC;
}

/* A connected Wii Remote at rest, pointing at the screen, plus a resting
 * Nunchuk -- what a GameCube controller drives when no remote is there. */
IN_GAP(e) void cp_neutral_remote(KPADStatus *s)
{
    const Tuning *t = tune();
    u32 *w = (u32 *)s;
    u32 i;
    for (i = 0; i < sizeof(KPADStatus) / 4; i++)
        w[i] = 0;
    s->acc.y = t->neg_one;
    s->acc_value = s->horizon.x = s->acc_vertical.x = t->one;
    s->dist = t->rest_dist;
}

/* ---- the hook ----------------------------------------------------------- */

IN_GAP(a) s32 cp_kpad_read(s32 chan, KPADStatus *s, u32 len)
{
    s32 n = KPADRead(chan, s, len);
    const Tuning *t;
    ChanState *st;
    GcInput gc;
    int have_remote, classic, gc_on, nunchuk;
    u32 rhold, rtrig, rrel, mhold, mtrig, mrel, hold, prev;
    Vec2 ptr, cam;

    if ((u32)chan >= 4)
        return n;
    st = &g_state[chan];

    have_remote = (n > 0) && (s->wpad_err == 0);
    classic = have_remote && (s->dev_type == WPAD_DEV_CLASSIC);
    nunchuk = have_remote && (s->dev_type == WPAD_DEV_FREESTYLE);
    gc_on = cp_gc_poll(chan, st, &gc);

    if (!classic && !gc_on) {
        /* Plain Wii Remote (or nothing): leave KPAD's data alone. */
        st->prev_hold = have_remote ? s->hold : 0;
        if (have_remote && s->dpd_valid_fg > 0) {
            st->last_real = s->pos;
            st->cursor = s->pos;
        }
        st->virt = 0;
        return n;
    }

    /* ---- buttons -------------------------------------------------------- */

    rhold = rtrig = rrel = 0;
    mhold = mtrig = mrel = 0;
    t = tune();
    ptr.x = ptr.y = cam.x = cam.y = t->zero;

    if (have_remote) {
        rhold = s->hold;
        rtrig = s->trig;
        rrel = s->release;
    }
    if (nunchuk)
        cam = s->ex.fs.stick;
    if (classic) {
        mhold = cp_remap(s->ex.cl.hold, k_map_classic);
        mtrig = cp_remap(s->ex.cl.trig, k_map_classic);
        mrel = cp_remap(s->ex.cl.release, k_map_classic);
        ptr = s->ex.cl.lstick;
        cam = s->ex.cl.rstick;
    }
    if (gc_on) {
        mhold |= gc.hold;
        cp_stick_merge(&ptr, &gc.ptr);
        cp_stick_merge(&cam, &gc.cam);
    }

    if (!have_remote)
        cp_neutral_remote(s);

    /* trig/release: edges of the merged hold, plus any press KPAD saw
     * between samples (KPAD reports those in trig/release only). */
    prev = st->prev_hold;
    hold = rhold | mhold;
    s->hold = hold;
    s->trig = (hold | rtrig | mtrig) & ~prev;
    s->release = (prev | rrel | mrel) & ~hold;
    st->prev_hold = hold;

    /* ---- Nunchuk -------------------------------------------------------- */

    t = tune();
    if (!nunchuk) {
        s->ex.fs.acc.x = s->ex.fs.acc.z = s->ex.fs.acc_speed = t->zero;
        s->ex.fs.acc.y = t->neg_one;
        s->ex.fs.acc_value = t->one;
    }
    if (mag2(cam.x, cam.y) <= t->deadzone2)
        cam.x = cam.y = t->zero;
    s->ex.fs.stick = cam;
    s->dev_type = WPAD_DEV_FREESTYLE;
    s->wpad_err = 0;

    /* ---- pointer -------------------------------------------------------- */

    cp_pointer(s, st, chan, &ptr,
               have_remote && !classic && s->dpd_valid_fg > 0);

    return (n > 0) ? n : 1;
}
