/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#ifdef UMEMCACHE_DEBUG
struct timespec extra_alloc_start, extra_alloc_end, alloc_start, alloc_end;
struct timespec extra_free_start, extra_free_end, free_start, free_end;
double extra_alloc_time, alloc_time, extra_free_time, free_time;
int extra_alloc_count = 0;
int extra_free_count = 0;
#endif /* UMEMCACHE_DEBUG */

/* Forward Declarations */
static void item_link_q(item *it);
static void item_unlink_q(item *it);

/* 2013_01_26: Revocated */
/* #ifdef UMEMCACHE_DEBUG */
/* static unsigned int count_child(item *parent); */
/* #endif */

/*
 * We only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed
 * items.
 */
#define ITEM_UPDATE_INTERVAL 60

#define LARGEST_ID POWER_LARGEST
typedef struct {
    uint64_t evicted;
    uint64_t evicted_nonzero;
    rel_time_t evicted_time;
    uint64_t reclaimed;
    uint64_t outofmemory;
    uint64_t tailrepairs;
    uint64_t expired_unfetched;
    uint64_t evicted_unfetched;
    /* Umemcache added 2012_12_10 */
    uint64_t sparelargered;
    uint64_t multiblocked;
    uint64_t extraalloc_failed;
    uint64_t children;
    uint64_t parents;
} itemstats_t;

static item *heads[LARGEST_ID];
static item *tails[LARGEST_ID];
static itemstats_t itemstats[LARGEST_ID];
static unsigned int sizes[LARGEST_ID];

/* /\* Umemcache added 2012_12_31 *\/ */
/* static item *parent_heads[LARGEST_ID]; */
/* static item *parent_tails[LARGEST_ID]; */

void item_stats_reset(void) {
    mutex_lock(&cache_lock);
    memset(itemstats, 0, sizeof(itemstats));
    mutex_unlock(&cache_lock);
}


/* Get the next CAS id for a new item. */
uint64_t get_cas_id(void) {
    static uint64_t cas_id = 0;
    return ++cas_id;
}

/* Enable this for reference-count debugging. */
#if 0
# define DEBUG_REFCNT(it,op)                            \
    fprintf(stderr, "item %x refcnt(%c) %d %c%c%c\n",   \
            it, op, it->refcount,         \
            (it->it_flags & ITEM_LINKED) ? 'L' : ' ',   \
            (it->it_flags & ITEM_SLABBED) ? 'S' : ' ')
#else
# define DEBUG_REFCNT(it,op) while(0)
#endif

#if UMEMCACHE_ITEMS_CHK
static void itemlist_check(void) {
    mutex_lock(&cache_lock);
    item **head;
    item **tail;
    //unsigned int *size;
    /* Item list check */
    int i;
    for (i = POWER_SMALLEST; i <= LARGEST_ID - POWER_SMALLEST + 1; i++) {
        head = &heads[i];
        tail = &tails[i];
        //size = &sizes[i];
        item *it = NULL;
        item *next = NULL;
        item *prev = NULL;
        unsigned int counter = 0;
        for (it = *head; it != NULL; it = next) {
            if (counter == 0) 
                assert(it->prev == NULL);
            assert((it->it_flags & ITEM_LINKED) != 0);
            next = it->next;
            counter++;
        }
        //assert(counter == *size);
        counter = 0;
        for (it = *tail; it != NULL; it = prev) {
            if (counter == 0)
                assert(it->next == NULL);
            prev = it->prev;
            counter++;
        }
        //assert(counter == *size);
    }
    mutex_unlock(&cache_lock);
}
#endif /* UMEMCACHE_ITEMS_CHK */

#ifdef UMEMCACHE_DEBUG
bool exist_item_in_itemlist(item *arg) {
    item **head;
#ifndef NDEBUG
    item **tail;
#endif
    //unsigned int *size;
    /* Item list check */
    int i;
    bool ret = false;
    for (i = POWER_SMALLEST; i <= LARGEST_ID - POWER_SMALLEST + 1; i++) {
        head = &heads[i];
#ifndef NDEBUG
        tail = &tails[i];
#endif
        item *it = NULL;
        item *next = NULL;
        for (it = *head; it != NULL; it = next) {
            if (it == arg) {
                assert(ret == false);
                ret = true;
            }
            next = it->next;
            if (it->next == NULL) assert(it == *tail);
        }
    }
    return ret;
}
#endif /* UMEMCACHE_DEBUG */

/**
 * Generates the variable-sized part of the header for an object.
 *
 * key     - The key
 * nkey    - The length of the key
 * flags   - key flags
 * nbytes  - Number of bytes to hold value and addition CRLF terminator
 * suffix  - Buffer for the "VALUE" line suffix (flags, size).
 * nsuffix - The length of the suffix is stored here.
 *
 * Returns the total size of the header.
 */
static size_t item_make_header(const uint8_t nkey, const int flags, const int nbytes,
                               char *suffix, uint8_t *nsuffix) {
    /* suffix is defined at 40 chars elsewhere.. */
    *nsuffix = (uint8_t) snprintf(suffix, 40, " %d %d\r\n", flags, nbytes - 2);
    return sizeof(item) + nkey + *nsuffix + nbytes;
}

/*@null@*/
item *do_item_alloc(char *key, const size_t nkey, const int flags, const rel_time_t exptime, const int nbytes) {

#ifdef UMEMCACHE_DEBUG
    UMEMCACHE_TIMER_START(&alloc_start);
#endif

    uint8_t nsuffix;
    item *it = NULL;
    char suffix[40];
    size_t ntotal = item_make_header(nkey + 1, flags, nbytes, suffix, &nsuffix);
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    unsigned int id = slabs_clsid(ntotal);
    if (id == 0)
        return 0;

    mutex_lock(&cache_lock);
    /* do a quick check if we have any expired items in the tail.. */
    item *search;
    rel_time_t oldest_live = settings.oldest_live;

    search = tails[id];
    if (search != NULL && (refcount_incr(&search->refcount) == 2)) {
        if ((search->exptime != 0 && search->exptime < current_time)
            || (search->time <= oldest_live && oldest_live <= current_time)) {  // dead by flush
            STATS_LOCK();
            stats.reclaimed++;
            STATS_UNLOCK();
            itemstats[id].reclaimed++;
            if ((search->it_flags & ITEM_FETCHED) == 0) {
                STATS_LOCK();
                stats.expired_unfetched++;
                STATS_UNLOCK();
                itemstats[id].expired_unfetched++;
            }
            it = search;
            slabs_adjust_mem_requested(it->slabs_clsid, ITEM_ntotal(it), ntotal);
            do_item_unlink_nolock(it, hash(ITEM_key(it), it->nkey, 0));
            /* Initialize the item block: */
            it->slabs_clsid = 0;
        } else if ((it = slabs_alloc(ntotal, id)) == NULL && (it = do_extra_item_alloc(ntotal, &id)) == NULL) {
            if (settings.evict_to_free == 0) {
                itemstats[id].outofmemory++;
                mutex_unlock(&cache_lock);
                return NULL;
            }
            itemstats[id].evicted++;
            itemstats[id].evicted_time = current_time - search->time;
            if (search->exptime != 0)
                itemstats[id].evicted_nonzero++;
            if ((search->it_flags & ITEM_FETCHED) == 0) {
                STATS_LOCK();
                stats.evicted_unfetched++;
                STATS_UNLOCK();
                itemstats[id].evicted_unfetched++;
            }
            STATS_LOCK();
            stats.evictions++;
            STATS_UNLOCK();
            it = search;
            slabs_adjust_mem_requested(it->slabs_clsid, ITEM_ntotal(it), ntotal);
            do_item_unlink_nolock(it, hash(ITEM_key(it), it->nkey, 0));
            /* Initialize the item block: */
            it->slabs_clsid = 0;

            /* If we've just evicted an item, and the automover is set to
             * angry bird mode, attempt to rip memory into this slab class.
             * TODO: Move valid object detection into a function, and on a
             * "successful" memory pull, look behind and see if the next alloc
             * would be an eviction. Then kick off the slab mover before the
             * eviction happens.
             */
            if (settings.slab_automove == 2)
                slabs_reassign(-1, id);
        } else {
            refcount_decr(&search->refcount);
        }
    } else {
        /* If the LRU is empty or locked, attempt to allocate memory */
        it = slabs_alloc(ntotal, id);
        if (it == NULL) it = do_extra_item_alloc(ntotal, &id);
        if (search != NULL)
            refcount_decr(&search->refcount);
    }

    if (it == NULL) {
        itemstats[id].outofmemory++;
        /* Last ditch effort. There was a very rare bug which caused
         * refcount leaks. We leave this just in case they ever happen again.
         * We can reasonably assume no item can stay locked for more than
         * three hours, so if we find one in the tail which is that old,
         * free it anyway.
         */
        if (search != NULL &&
            search->refcount != 2 &&
            search->time + TAIL_REPAIR_TIME < current_time) {
            itemstats[id].tailrepairs++;
            search->refcount = 1;
            do_item_unlink_nolock(search, hash(ITEM_key(search), search->nkey, 0));
        }
        mutex_unlock(&cache_lock);
        return NULL;
    }

    assert(it->slabs_clsid == 0);
    assert(it != heads[id]);

    /* Item initialization can happen outside of the lock; the item's already
     * been removed from the slab LRU.
     */
    it->refcount = 1;     /* the caller will have a reference */
    mutex_unlock(&cache_lock);
    it->next = it->prev = it->h_next = 0;
    it->slabs_clsid = id;

    DEBUG_REFCNT(it, '*');
    if ((it->it_flags & ITEM_CHILD) == 0)
        it->it_flags = settings.use_cas ? ITEM_CAS : 0;
    else
        it->it_flags = settings.use_cas ? (ITEM_CAS | ITEM_CHILD) : ITEM_CHILD;
    it->nkey = nkey;
    it->nbytes = nbytes;
    memcpy(ITEM_key(it), key, nkey);
    it->exptime = exptime;
    memcpy(ITEM_suffix(it), suffix, (size_t)nsuffix);
    it->nsuffix = nsuffix;

#ifdef UMEMCACHE_DEBUG
    UMEMCACHE_TIMER_END(&alloc_end, &alloc_start, &alloc_time);
#endif

#if UMEMCACHE_ITEMS_CHK
    itemlist_check();
    assert(!exist_item_in_freelist(it));
#endif

    return it;
}

/* Umemcache added 2012_11_30 */
/**
 * @param often-used class item
 * Return an extra-item
 * Require cache_lock
 */
item *do_extra_item_alloc(const size_t ntotal, unsigned int *clsid) {

#ifdef UMEMCACHE_DEBUG
    UMEMCACHE_EXTRA_ALLOC_COUNT();
    UMEMCACHE_TIMER_START(&extra_alloc_start);
#endif

    unsigned int new_clsid;
    item *ret = NULL;
    
    new_clsid = slabs_idle_clsid(*clsid);
    if (new_clsid == 0) {
        itemstats[*clsid].extraalloc_failed++;
        return NULL;
    }

#if !defined(UMEMCACHE_DEBUG) || UMEMCACHE_DEBUG_MULTIBLOCK
    uint8_t parent_nkey = 1;
    int parent_flags = ITEM_PARENT;
    int parent_nbytes;
    char parent_suffix[10] = "/r/n";
    uint8_t parent_nsuffix = 2;
    item *parent = NULL;
    size_t parent_ntotal;
        
    /* uint8_t parent_nsuffix_tmp = -1; */
    /* while (parent_nsuffix_tmp != parent_nsuffix) { */
    /*     parent_nsuffix_tmp = parent_nsuffix; */
    /*     parent_ntotal = item_make_header(parent_nkey, parent_flags, parent_nbytes, parent_suffix, &parent_nsuffix); */
    /*     parent_nbytes = slabs_size(new_clsid) - sizeof(item) - (settings.use_cas ? sizeof(uint64_t) : 0) - parent_nkey - parent_nsuffix; */
    /* } */
    
    parent_ntotal = slabs_size(new_clsid);
    parent_nbytes = parent_ntotal - sizeof(item) - (settings.use_cas ? sizeof(uint64_t) : 0) - parent_nkey - 1 - parent_nsuffix;

#endif /* UMEMCACHE_DEBUG_MULTIBLOCK */

    ret = slabs_alloc(ntotal, new_clsid);

#if !defined(UMEMCACHE_DEBUG) || UMEMCACHE_DEBUG_MULTIBLOCK
    if (parent_nbytes < ((slabs_size(*clsid) + sizeof(child_prefix)) * 2) || (ret->it_flags & ITEM_CHILD) != 0)
#endif
    {
#if !defined(UMEMCACHE_DEBUG) || UMEMCACHE_DEBUG_SPARELARGER
        assert(ret != NULL);
        itemstats[*clsid].sparelargered++;
        *clsid = new_clsid;
#else
        slabs_free(ret, ntotal, new_clsid);
        ret = NULL;
#endif /* UMEMCACHE_DEBUG_SPARELARGER */
    }
#if !defined(UMEMCACHE_DEBUG) || UMEMCACHE_DEBUG_MULTIBLOCK
    else 
    {
        slabs_adjust_mem_requested(new_clsid, ntotal, parent_ntotal);
        parent = ret;
        assert(parent != NULL);
        assert(parent->slabs_clsid == 0);
        assert(parent != heads[new_clsid]);
        assert(parent != tails[new_clsid]);

        parent->refcount = 1;
        parent->next = parent->prev = parent->h_next = 0;
        parent->slabs_clsid = new_clsid;
        DEBUG_REFCNT(parent, '*');
        parent->it_flags = settings.use_cas ? (parent_flags | ITEM_CAS) : parent_flags;
        parent->nkey = parent_nkey;
        parent->nbytes = parent_nbytes;
        memcpy(ITEM_key(parent), "P", parent_nkey);
        parent->exptime = 0;
        memcpy(ITEM_suffix(parent), parent_suffix, (size_t)parent_nsuffix);
        parent->nsuffix = parent_nsuffix;
        /* item_link_q(parent); */
        
        split_parent_into_freelist((char *)parent, *clsid);
        ret = slabs_alloc(ntotal, *clsid);
        assert(ret != NULL && ret != parent);
        assert((ret->it_flags & ITEM_CHILD) != 0);
        itemstats[*clsid].multiblocked++;
    }
#endif /* UMEMCACHE_DEBUG_MULTIBLOCK */

#ifdef UMEMCACHE_DEBUG
    UMEMCACHE_TIMER_END(&extra_alloc_end, &extra_alloc_start, &extra_alloc_time);
#endif

    //    if (parent != NULL) assert(parent->refcount == count_child(parent) + 1);

    return ret;
}


void item_free(item *it) {
    size_t ntotal = ITEM_ntotal(it);
    unsigned int clsid;
    assert((it->it_flags & ITEM_LINKED) == 0);
    assert(it != heads[it->slabs_clsid]);
    assert(it != tails[it->slabs_clsid]);
    assert(it->refcount == 0);

    /* so slab size changer can tell later if item is already free or not */
    clsid = it->slabs_clsid;
    it->slabs_clsid = 0;
    DEBUG_REFCNT(it, 'F');
    if (it->it_flags & ITEM_CHILD) {
        /* if it is child, don't free */
#ifdef UMEMCACHE_DEBUG
        UMEMCACHE_EXTRA_FREE_COUNT();
        UMEMCACHE_TIMER_START(&extra_free_start);
#endif
        item *parent = ((child_prefix *)ITEM_child_prefix(it))->parent;
        assert((parent->it_flags & ITEM_PARENT) != 0);
        //        assert(parent->refcount == count_child(parent) + 2);
        /* Child recycle is revocated : 2013_02_07 */
        /* if (slabs_freeblocks(parent->slabs_clsid) != 0) { */
        /*     slabs_free(it, ntotal, clsid); */
        /* }             */
        /* else */ 
        if ((refcount_decr(&parent->refcount) == 1) /*&& (count_child(parent) == 0) */) {
            parent->it_flags &= ~ITEM_PARENT;
            do_item_remove(parent);
        }
            
#ifdef UMEMCACHE_DEBUG
        UMEMCACHE_TIMER_END(&extra_free_end, &extra_free_start, &extra_free_time);
#endif
    } else {
        slabs_free(it, ntotal, clsid);
    }
}

/* 2013_01_21: Revocated */
/* bool parent_empty_nester(item *parent) { */
/*     char *ptr = ITEM_data(parent); */
/*     child_prefix *prefix = NULL; */
/*     item *child = NULL; */
/*     size_t remain = parent->nbytes; */

/*     assert(parent != NULL && (parent->it_flags & ITEM_PARENT)); */

/*     while (remain > 0) { */
/*         prefix = (child_prefix *)ptr; */
/*         assert(prefix->parent == parent); */
/*         ptr += sizeof(child_prefix); */
/*         child = (item *)ptr; */
/*         assert((child->it_flags & ITEM_CHILD) != 0); */
/*         assert((child->it_flags & ITEM_SLABBED) == 0); */
/*         assert(!exist_item_in_itemlist(child)); */
/*         if ((child->it_flags & ITEM_LINKED) || (child->it_flags & ITEM_SLABBED)) */
/*             return false; */
/*         ptr += slabs_size(prefix->slabs_clsid); */
/*         remain = remain - sizeof(child_prefix) - slabs_size(prefix->slabs_clsid); */
/*     }  */
/*     assert(remain == 0); */
        
/*     return true; */
/* } */

/* 2013_01_26: Revocated */
/* #ifdef UMEMCACHE_DEBUG */
/* /\* Umemcache: clone of parent_empty_nester *\/ */
/* static unsigned int count_child(item *parent) { */
/*     char *ptr = ITEM_data(parent); */
/*     child_prefix *prefix = NULL; */
/*     item *child = NULL; */
/*     size_t remain = parent->nbytes; */
/*     unsigned int count = 0; */

/*     assert(parent != NULL && (parent->it_flags & ITEM_PARENT)); */

/*     while (remain > 0) { */
/*         prefix = (child_prefix *)ptr; */
/*         assert(prefix->parent == parent); */
/*         ptr += sizeof(child_prefix); */
/*         child = (item *)ptr; */
/*         assert(child->it_flags & ITEM_CHILD); */
/*         ptr += slabs_size(prefix->slabs_clsid); */
/*         if ((child->it_flags & ITEM_LINKED) || (child->it_flags & ITEM_SLABBED)) */
/*             count++; */
/*         remain = remain - sizeof(child_prefix) - slabs_size(prefix->slabs_clsid); */
/*     }  */
/*     assert(remain == 0); */
        
/*     return count; */
/* } */
/* #endif /\* UMEMCACHE_DEBUG *\/ */


/**
 * Returns true if an item will fit in the cache (its size does not exceed
 * the maximum for a cache entry.)
 */
bool item_size_ok(const size_t nkey, const int flags, const int nbytes) {
    char prefix[40];
    uint8_t nsuffix;

    size_t ntotal = item_make_header(nkey + 1, flags, nbytes,
                                     prefix, &nsuffix);
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    return slabs_clsid(ntotal) != 0;
}

static void item_link_q(item *it) { /* item is the new head */
    item **head, **tail;
    assert(it->slabs_clsid < LARGEST_ID);
    assert((it->it_flags & ITEM_SLABBED) == 0);

    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];
    assert(it != *head);
    assert((*head && *tail) || (*head == 0 && *tail == 0));
    it->prev = 0;
    it->next = *head;
    if (it->next) it->next->prev = it;
    *head = it;
    if (*tail == 0) *tail = it;
    sizes[it->slabs_clsid]++;
    return;
}

static void item_unlink_q(item *it) {
    item **head, **tail;
    assert(it->slabs_clsid < LARGEST_ID);
    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];

    if (*head == it) {
        assert(it->prev == 0);
        *head = it->next;
    }
    if (*tail == it) {
        assert(it->next == 0);
        *tail = it->prev;
    }
    assert(it->next != it);
    assert(it->prev != it);

    if (it->next) it->next->prev = it->prev;
    if (it->prev) it->prev->next = it->next;
    sizes[it->slabs_clsid]--;
    return;
}

int do_item_link(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_LINK(ITEM_key(it), it->nkey, it->nbytes);
    assert((it->it_flags & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    mutex_lock(&cache_lock);
    it->it_flags |= ITEM_LINKED;
    it->time = current_time;

    STATS_LOCK();
    stats.curr_bytes += ITEM_ntotal(it);
    stats.curr_items += 1;
    stats.total_items += 1;
    STATS_UNLOCK();

    /* Allocate a new CAS ID on link. */
    ITEM_set_cas(it, (settings.use_cas) ? get_cas_id() : 0);
    assoc_insert(it, hv);
    item_link_q(it);
    refcount_incr(&it->refcount);
    mutex_unlock(&cache_lock);

    return 1;
}

void do_item_unlink(item *it, const uint32_t hv) {
#ifdef UMEMCACHE_DEBUG
    UMEMCACHE_TIMER_START(&free_start);
#endif
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nkey, it->nbytes);
    mutex_lock(&cache_lock);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey, hv);
        item_unlink_q(it);
        /* if ((it->it_flags & ITEM_CHILD) == 0) { */
/*             do_item_remove(it); */
/*         } else { */
/* #ifdef UMEMCACHE_DEBUG */
/*             UMEMCACHE_EXTRA_FREE_COUNT(); */
/*             UMEMCACHE_TIMER_START(&extra_free_start); */
/* #endif */
/*             item *parent = ((child_prefix *)ITEM_child_prefix(it))->parent; */
/*             assert((parent->it_flags & ITEM_PARENT) != 0); */
/*             assert(parent->refcount == count_child(parent) + 1); */
/*             if ((refcount_decr(&parent->refcount) == 1) && (parent_empty_nester(parent))) */
/*                 do_item_remove(parent); */
/* #ifdef UMEMCACHE_DEBUG */
/*             UMEMCACHE_TIMER_END(&extra_free_end, &extra_free_start, &extra_free_time); */
/* #endif */
/*         } */
        do_item_remove(it);
    }
    mutex_unlock(&cache_lock);
#ifdef UMEMCACHE_DEBUG
        UMEMCACHE_TIMER_END(&free_end, &free_start, &free_time);
#endif
}

/* FIXME: Is it necessary to keep this copy/pasted code? */
void do_item_unlink_nolock(item *it, const uint32_t hv) {
#ifdef UMEMCACHE_DEBUG
        UMEMCACHE_TIMER_START(&free_start);
#endif
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nkey, it->nbytes);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey, hv);
        item_unlink_q(it);
        /* if ((it->it_flags & ITEM_CHILD) == 0) { */
/*             do_item_remove(it); */
/*         } else { */
/* #ifdef UMEMCACHE_DEBUG */
/*             UMEMCACHE_EXTRA_FREE_COUNT(); */
/*             UMEMCACHE_TIMER_START(&extra_free_start); */
/* #endif */
/*             item *parent = ((child_prefix *)ITEM_child_prefix(it))->parent; */
/*             assert((parent->it_flags & ITEM_PARENT) != 0); */
/*             assert(parent->refcount == count_child(parent) + 1); */
/*             if ((refcount_decr(&parent->refcount) == 1) && (parent_empty_nester(parent))) */
/*                 do_item_remove(parent); */
/* #ifdef UMEMCACHE_DEBUG */
/*             UMEMCACHE_TIMER_END(&extra_free_end, &extra_free_start, &extra_free_time); */
/* #endif */
/*         } */
        do_item_remove(it);
    }
#ifdef UMEMCACHE_DEBUG
        UMEMCACHE_TIMER_END(&free_end, &free_start, &free_time);
#endif
}

void do_item_remove(item *it) {
    MEMCACHED_ITEM_REMOVE(ITEM_key(it), it->nkey, it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);

    if (refcount_decr(&it->refcount) == 0 && it->it_flags) {
        item_free(it);
    }
}

void do_item_update(item *it) {
    MEMCACHED_ITEM_UPDATE(ITEM_key(it), it->nkey, it->nbytes);
    if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
        assert((it->it_flags & ITEM_SLABBED) == 0);

        mutex_lock(&cache_lock);
        if ((it->it_flags & ITEM_LINKED) != 0) {
            item_unlink_q(it);
            it->time = current_time;
            item_link_q(it);
        }
        mutex_unlock(&cache_lock);
    }
}

int do_item_replace(item *it, item *new_it, const uint32_t hv) {
    MEMCACHED_ITEM_REPLACE(ITEM_key(it), it->nkey, it->nbytes,
                           ITEM_key(new_it), new_it->nkey, new_it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);

    do_item_unlink(it, hv);
    return do_item_link(new_it, hv);
}

/*@null@*/
char *do_item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes) {
    unsigned int memlimit = 2 * 1024 * 1024;   /* 2MB max response size */
    char *buffer;
    unsigned int bufcurr;
    item *it;
    unsigned int len;
    unsigned int shown = 0;
    char key_temp[KEY_MAX_LENGTH + 1];
    char temp[512];

    it = heads[slabs_clsid];

    buffer = malloc((size_t)memlimit);
    if (buffer == 0) return NULL;
    bufcurr = 0;

    while (it != NULL && (limit == 0 || shown < limit)) {
        assert(it->nkey <= KEY_MAX_LENGTH);
        /* Copy the key since it may not be null-terminated in the struct */
        strncpy(key_temp, ITEM_key(it), it->nkey);
        key_temp[it->nkey] = 0x00; /* terminate */
        len = snprintf(temp, sizeof(temp), "ITEM %s [%d b; %lu s]\r\n",
                       key_temp, it->nbytes - 2,
                       (unsigned long)it->exptime + process_started);
        if (bufcurr + len + 6 > memlimit)  /* 6 is END\r\n\0 */
            break;
        memcpy(buffer + bufcurr, temp, len);
        bufcurr += len;
        shown++;
        it = it->next;
    }

    memcpy(buffer + bufcurr, "END\r\n", 6);
    bufcurr += 5;

    *bytes = bufcurr;
    return buffer;
}

void item_stats_evictions(uint64_t *evicted) {
    int i;
    mutex_lock(&cache_lock);
    for (i = 0; i < LARGEST_ID; i++) {
        evicted[i] = itemstats[i].evicted;
    }
    mutex_unlock(&cache_lock);
}

void do_item_stats(ADD_STAT add_stats, void *c) {
    int i;
    for (i = 0; i < LARGEST_ID; i++) {
        if (tails[i] != NULL) {
            const char *fmt = "items:%d:%s";
            char key_str[STAT_KEY_LEN];
            char val_str[STAT_VAL_LEN];
            int klen = 0, vlen = 0;
            if (tails[i] == NULL) {
                /* We removed all of the items in this slab class */
                continue;
            }
            APPEND_NUM_FMT_STAT(fmt, i, "number", "%u", sizes[i]);
            APPEND_NUM_FMT_STAT(fmt, i, "age", "%u", current_time - tails[i]->time);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted",
                                "%llu", (unsigned long long)itemstats[i].evicted);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted_nonzero",
                                "%llu", (unsigned long long)itemstats[i].evicted_nonzero);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted_time",
                                "%u", itemstats[i].evicted_time);
            APPEND_NUM_FMT_STAT(fmt, i, "outofmemory",
                                "%llu", (unsigned long long)itemstats[i].outofmemory);
            APPEND_NUM_FMT_STAT(fmt, i, "tailrepairs",
                                "%llu", (unsigned long long)itemstats[i].tailrepairs);
            APPEND_NUM_FMT_STAT(fmt, i, "reclaimed",
                                "%llu", (unsigned long long)itemstats[i].reclaimed);
            APPEND_NUM_FMT_STAT(fmt, i, "expired_unfetched",
                                "%llu", (unsigned long long)itemstats[i].expired_unfetched);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted_unfetched",
                                "%llu", (unsigned long long)itemstats[i].evicted_unfetched);
            /* Umemcache added 2012_12_10 */
            APPEND_NUM_FMT_STAT(fmt, i, "sparelargered",
                                "%llu", (unsigned long long)itemstats[i].sparelargered);
            APPEND_NUM_FMT_STAT(fmt, i, "multiblocked",
                                "%llu", (unsigned long long)itemstats[i].multiblocked);
            APPEND_NUM_FMT_STAT(fmt, i, "extraalloc_failed",
                                "%llu", (unsigned long long)itemstats[i].extraalloc_failed);
        }
    }

    /* getting here means both ascii and binary terminators fit */
    add_stats(NULL, 0, NULL, 0, c);
}

/** dumps out a list of objects of each size, with granularity of 32 bytes */
/*@null@*/
void do_item_stats_sizes(ADD_STAT add_stats, void *c) {

    /* max 1MB object, divided into 32 bytes size buckets */
    const int num_buckets = 32768;
    unsigned int *histogram = calloc(num_buckets, sizeof(int));

    if (histogram != NULL) {
        int i;

        /* build the histogram */
        for (i = 0; i < LARGEST_ID; i++) {
            item *iter = heads[i];
            while (iter) {
                int ntotal = ITEM_ntotal(iter);
                int bucket = ntotal / 32;
                if ((ntotal % 32) != 0) bucket++;
                if (bucket < num_buckets) histogram[bucket]++;
                iter = iter->next;
            }
        }

        /* write the buffer */
        for (i = 0; i < num_buckets; i++) {
            if (histogram[i] != 0) {
                char key[8];
                snprintf(key, sizeof(key), "%d", i * 32);
                APPEND_STAT(key, "%u", histogram[i]);
            }
        }
        free(histogram);
    }
    add_stats(NULL, 0, NULL, 0, c);
}

/** wrapper around assoc_find which does the lazy expiration logic */
item *do_item_get(const char *key, const size_t nkey, const uint32_t hv) {
    mutex_lock(&cache_lock);
    item *it = assoc_find(key, nkey, hv);
    if (it != NULL) {
        refcount_incr(&it->refcount);
        /* Optimization for slab reassignment. prevents popular items from
         * jamming in busy wait. Can only do this here to satisfy lock order
         * of item_lock, cache_lock, slabs_lock. */
        if (slab_rebalance_signal &&
            ((void *)it >= slab_rebal.slab_start && (void *)it < slab_rebal.slab_end)) {
            do_item_unlink_nolock(it, hv);
            do_item_remove(it);
            it = NULL;
        }
    }
    mutex_unlock(&cache_lock);
    int was_found = 0;

    if (settings.verbose > 2) {
        if (it == NULL) {
            fprintf(stderr, "> NOT FOUND %s", key);
        } else {
            fprintf(stderr, "> FOUND KEY %s", ITEM_key(it));
            was_found++;
        }
    }

    if (it != NULL) {
        if (settings.oldest_live != 0 && settings.oldest_live <= current_time &&
            it->time <= settings.oldest_live) {
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
            if (was_found) {
                fprintf(stderr, " -nuked by flush");
            }
        } else if (it->exptime != 0 && it->exptime <= current_time) {
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
            if (was_found) {
                fprintf(stderr, " -nuked by expire");
            }
        } else {
            it->it_flags |= ITEM_FETCHED;
            DEBUG_REFCNT(it, '+');
        }
    }

    if (settings.verbose > 2)
        fprintf(stderr, "\n");

    return it;
}

item *do_item_touch(const char *key, size_t nkey, uint32_t exptime,
                    const uint32_t hv) {
    item *it = do_item_get(key, nkey, hv);
    if (it != NULL) {
        it->exptime = exptime;
    }
    return it;
}

/* expires items that are more recent than the oldest_live setting. */
void do_item_flush_expired(void) {
    int i;
    item *iter, *next;
    if (settings.oldest_live == 0)
        return;
    for (i = 0; i < LARGEST_ID; i++) {
        /* The LRU is sorted in decreasing time order, and an item's timestamp
         * is never newer than its last access time, so we only need to walk
         * back until we hit an item older than the oldest_live time.
         * The oldest_live checking will auto-expire the remaining items.
         */
        for (iter = heads[i]; iter != NULL; iter = next) {
            if (iter->time >= settings.oldest_live) {
                next = iter->next;
                if ((iter->it_flags & ITEM_SLABBED) == 0) {
                    do_item_unlink_nolock(iter, hash(ITEM_key(iter), iter->nkey, 0));
                }
            } else {
                /* We've hit the first old item. Continue to the next queue. */
                break;
            }
        }
    }
}
