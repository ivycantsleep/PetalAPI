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
#include <basedll.h>
#include "_list.h" 

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
void list_add_after( struct list *elem, struct list *to_add )
{
    to_add->next = elem->next;
    to_add->prev = elem;
    elem->next->prev = to_add;
    elem->next = to_add;
}

/* add an element before the specified one */
void list_add_before( struct list *elem, struct list *to_add )
{
    to_add->next = elem;
    to_add->prev = elem->prev;
    elem->prev->next = to_add;
    elem->prev = to_add;
}

/* add element at the head of the list */
void list_add_head( struct list *list, struct list *elem )
{
    list_add_after( list, elem );
}

/* add element at the tail of the list */
void list_add_tail( struct list *list, struct list *elem )
{
    list_add_before( list, elem );
}

/* remove an element from its list */
void list_remove( struct list *elem )
{
    elem->next->prev = elem->prev;
    elem->prev->next = elem->next;
}

/* get the next element */
struct list *list_next( const struct list *list, const struct list *elem )
{
    struct list *ret = elem->next;
    if (elem->next == list) ret = NULL;
    return ret;
}

/* get the previous element */
struct list *list_prev( const struct list *list, const struct list *elem )
{
    struct list *ret = elem->prev;
    if (elem->prev == list) ret = NULL;
    return ret;
}

/* get the first element */
struct list *list_head( const struct list *list )
{
    return list_next( list, list );
}

/* get the last element */
struct list *list_tail( const struct list *list )
{
    return list_prev( list, list );
}

/* check if a list is empty */
int list_empty( const struct list *list )
{
    return list->next == list;
}

/* initialize a list */
void list_init( struct list *list )
{
    list->next = list->prev = list;
}

/* count the elements of a list */
unsigned int list_count( const struct list *list )
{
    unsigned count = 0;
    const struct list *ptr;
    for (ptr = list->next; ptr != list; ptr = ptr->next) count++;
    return count;
}

/* move all elements from src to the tail of dst */
void list_move_tail( struct list *dst, struct list *src )
{
    if (list_empty(src)) return;

    dst->prev->next = src->next;
    src->next->prev = dst->prev;
    dst->prev = src->prev;
    src->prev->next = dst;
    list_init(src);
}

/* move all elements from src to the head of dst */
void list_move_head( struct list *dst, struct list *src )
{
    if (list_empty(src)) return;

    dst->next->prev = src->prev;
    src->prev->next = dst->next;
    dst->next = src->next;
    src->next->prev = dst;
    list_init(src);
}
