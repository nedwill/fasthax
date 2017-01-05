#ifndef __UTIL_H
#define __UTIL_H

void wait_for_user(void);

void *convertVAToPA(const void *addr);
void flushEntireCaches(void);

#endif /* __UTIL_H */
