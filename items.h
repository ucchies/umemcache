/* See items.c */
uint64_t get_cas_id(void);

/*@null@*/
item *do_item_alloc(char *key, const size_t nkey, const int flags, const rel_time_t exptime, const int nbytes);
void item_free(item *it);
bool item_size_ok(const size_t nkey, const int flags, const int nbytes);

int  do_item_link(item *it, const uint32_t hv);     /** may fail if transgresses limits */
void do_item_unlink(item *it, const uint32_t hv);
void do_item_unlink_nolock(item *it, const uint32_t hv);
void do_item_remove(item *it);
void do_item_update(item *it);   /** update LRU time to current and reposition */
int  do_item_replace(item *it, item *new_it, const uint32_t hv);

/*@null@*/
char *do_item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes);
void do_item_stats(ADD_STAT add_stats, void *c);
/*@null@*/
void do_item_stats_sizes(ADD_STAT add_stats, void *c);
void do_item_flush_expired(void);

item *do_item_get(const char *key, const size_t nkey, const uint32_t hv);
item *do_item_touch(const char *key, const size_t nkey, uint32_t exptime, const uint32_t hv);
void item_stats_reset(void);
extern pthread_mutex_t cache_lock;
void item_stats_evictions(uint64_t *evicted);

/* Umemcache added 2012_12_07 */
item *do_extra_item_alloc(const size_t ntotal, unsigned int *clsid);
bool parent_empty_nester(item *parent);

/* Umemcache added 2013_01_15 */
bool exist_item_in_itemlist(item *arg);

/* Umemcache added 2012_12_07
 * 2012_12_07: moved from slabs.c AND modified
 */
/* #ifndef UMEMCACHE_DEBUG */
/* #define UMEMCACHE_DEBUG */
/* //#undef NDEBUG */
/* #include <sys/time.h> */

/* extern struct timespec extra_alloc_start, extra_alloc_end, alloc_start, alloc_end; */
/* extern struct timespec extra_free_start, extra_free_end, free_start, free_end; */
/* extern double extra_alloc_time, alloc_time, extra_free_time, free_time; */
/* extern int extra_alloc_count; */
/* extern int extra_free_count; */
/* #define UMEMCACHE_TIMER_START(start_time) clock_gettime(CLOCK_PROCESS_CPUTIME_ID, (start_time)) */
/* #define UMEMCACHE_TIMER_END(end_time,start_time,result) clock_gettime(CLOCK_PROCESS_CPUTIME_ID, (end_time)); \ */
/*     (*result) += ((end_time)->tv_sec - (start_time)->tv_sec) +           \ */
/*         (((end_time)->tv_nsec - (start_time)->tv_nsec)*1.0E-9) */
/* //#define UMEMCACHE_TIMER_GETTIME() extra_alloc_time; */
/* #define UMEMCACHE_TIMER_RESET() extra_alloc_time = alloc_time = extra_free_time = free_time = 0 */
/* #define UMEMCACHE_EXTRA_ALLOC_COUNT() extra_alloc_count++; */
/* #define UMEMCACHE_EXTRA_FREE_COUNT() extra_free_count++; */

/* #define UMEMCACHE_DEBUG_SPARELARGER 1 */
/* #define UMEMCACHE_DEBUG_MULTIBLOCK 1 */
/* #define UMEMCACHE_ITEMS_CHK 0 */
/* #define UMEMCACHE_SLABS_CHK 0 */


/* #endif /\* UMEMCACHE_DEBUG *\/ */
