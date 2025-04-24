/*
 * Linked lists support
 *
 * Copyright (C) 2002 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_SERVER_LIST_H
#define __WINE_SERVER_LIST_H

#include <stddef.h>

struct list
{
    struct list *next;
    struct list *prev;
};

/* Define a list like so:
 *
 *   struct gadget
 *   {
 *       struct list  entry;   <-- doesn't have to be the first item in the struct
 *       int          a, b;
 *   };
 *
 *   static struct list global_gadgets = LIST_INIT( global_gadgets );
 *
 * or
 *
 *   struct some_global_thing
 *   {
 *       struct list gadgets;
 *   };
 *
 *   list_init( &some_global_thing->gadgets );
 *
 * Manipulate it like this:
 *
 *   list_add_head( &global_gadgets, &new_gadget->entry );
 *   list_remove( &new_gadget->entry );
 *   list_add_after( &some_random_gadget->entry, &new_gadget->entry );
 *
 * And to iterate over it:
 *
 *   struct gadget *gadget;
 *   LIST_FOR_EACH_ENTRY( gadget, &global_gadgets, struct gadget, entry )
 *   {
 *       ...
 *   }
 *
 */

/* add an element after the specified one */
void list_add_after( struct list *elem, struct list *to_add );

/* add an element before the specified one */
void list_add_before( struct list *elem, struct list *to_add );

/* add element at the head of the list */
void list_add_head( struct list *list, struct list *elem );

/* add element at the tail of the list */
void list_add_tail( struct list *list, struct list *elem );

/* remove an element from its list */
void list_remove( struct list *elem );

/* get the next element */
struct list *list_next( const struct list *list, const struct list *elem );

/* get the previous element */
struct list *list_prev( const struct list *list, const struct list *elem );

/* get the first element */
struct list *list_head( const struct list *list );

/* get the last element */
struct list *list_tail( const struct list *list );

/* check if a list is empty */
int list_empty( const struct list *list );

/* initialize a list */
void list_init( struct list *list );

/* count the elements of a list */
unsigned int list_count( const struct list *list );

/* move all elements from src to the tail of dst */
void list_move_tail( struct list *dst, struct list *src );
/* move all elements from src to the head of dst */
void list_move_head( struct list *dst, struct list *src );

/* iterate through the list */
#define LIST_FOR_EACH(cursor,list) \
    for ((cursor) = (list)->next; (cursor) != (list); (cursor) = (cursor)->next)

/* iterate through the list, with safety against removal */
#define LIST_FOR_EACH_SAFE(cursor, cursor2, list) \
    for ((cursor) = (list)->next, (cursor2) = (cursor)->next; \
         (cursor) != (list); \
         (cursor) = (cursor2), (cursor2) = (cursor)->next)

/* iterate through the list using a list entry */
#define LIST_FOR_EACH_ENTRY(elem, list, type, field) \
    for ((elem) = LIST_ENTRY((list)->next, type, field); \
         &(elem)->field != (list); \
         (elem) = LIST_ENTRY((elem)->field.next, type, field))

/* iterate through the list using a list entry, with safety against removal */
#define LIST_FOR_EACH_ENTRY_SAFE(cursor, cursor2, list, type, field) \
    for ((cursor) = LIST_ENTRY((list)->next, type, field), \
         (cursor2) = LIST_ENTRY((cursor)->field.next, type, field); \
         &(cursor)->field != (list); \
         (cursor) = (cursor2), \
         (cursor2) = LIST_ENTRY((cursor)->field.next, type, field))

/* iterate through the list in reverse order */
#define LIST_FOR_EACH_REV(cursor,list) \
    for ((cursor) = (list)->prev; (cursor) != (list); (cursor) = (cursor)->prev)

/* iterate through the list in reverse order, with safety against removal */
#define LIST_FOR_EACH_SAFE_REV(cursor, cursor2, list) \
    for ((cursor) = (list)->prev, (cursor2) = (cursor)->prev; \
         (cursor) != (list); \
         (cursor) = (cursor2), (cursor2) = (cursor)->prev)

/* iterate through the list in reverse order using a list entry */
#define LIST_FOR_EACH_ENTRY_REV(elem, list, type, field) \
    for ((elem) = LIST_ENTRY((list)->prev, type, field); \
         &(elem)->field != (list); \
         (elem) = LIST_ENTRY((elem)->field.prev, type, field))

/* iterate through the list in reverse order using a list entry, with safety against removal */
#define LIST_FOR_EACH_ENTRY_SAFE_REV(cursor, cursor2, list, type, field) \
    for ((cursor) = LIST_ENTRY((list)->prev, type, field), \
         (cursor2) = LIST_ENTRY((cursor)->field.prev, type, field); \
         &(cursor)->field != (list); \
         (cursor) = (cursor2), \
         (cursor2) = LIST_ENTRY((cursor)->field.prev, type, field))

/* macros for statically initialized lists */
#undef LIST_INIT
#define LIST_INIT(list)  { &(list), &(list) }

/* get pointer to object containing list element */
#undef LIST_ENTRY
#define LIST_ENTRY(elem, type, field) \
    ((type *)((char *)(elem) - offsetof(type, field)))

#endif  /* __WINE_SERVER_LIST_H */
