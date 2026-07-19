#include "Serach_UI.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "kdbx/kdbx_loader.h"
#include "lvgl.h"
#include "ui_nav.h"
#include "ui_password_detail.h"
#include "ui_password_manager.h"

#define SEARCH_UI_WIDTH       480
#define SEARCH_MAX_RESULTS    24

typedef enum {
    SEARCH_KEYBOARD_LOWER,
    SEARCH_KEYBOARD_UPPER,
    SEARCH_KEYBOARD_SYMBOL,
} search_keyboard_mode_t;

typedef struct {
    size_t entry_index;
} search_result_item_t;

static lv_obj_t *s_query_textarea;
static lv_obj_t *s_results_panel;
static lv_obj_t *s_keyboard;
static search_keyboard_mode_t s_keyboard_mode;
static search_result_item_t s_result_items[SEARCH_MAX_RESULTS];

static const char *s_lower_map[] = {
    "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "\n",
    "a", "s", "d", "f", "g", "h", "j", "k", "l", "\n",
    LV_SYMBOL_BACKSPACE, "z", "x", "c", "v", "b", "n", "m", LV_SYMBOL_OK, ""
};

static const char *s_upper_map[] = {
    "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "\n",
    "A", "S", "D", "F", "G", "H", "J", "K", "L", "\n",
    LV_SYMBOL_BACKSPACE, "Z", "X", "C", "V", "B", "N", "M", LV_SYMBOL_OK, ""
};

static const char *s_symbol_map[] = {
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "\n",
    "-", "_", ".", "@", "/", ":", "#", "&", "*", "\n",
    LV_SYMBOL_BACKSPACE, "!", "?", "+", "=", "(", ")", "'", LV_SYMBOL_OK, ""
};

static char lower_ascii(char ch)
{
    return (char)tolower((unsigned char)ch);
}

static bool title_matches_query(const char *title, const char *query)
{
    if (!query || query[0] == '\0') {
        return true;
    }

    const char *title_cursor = title;
    const char *query_cursor = query;
    while (*title_cursor && *query_cursor) {
        if (lower_ascii(*title_cursor) == lower_ascii(*query_cursor)) {
            query_cursor++;
        }
        title_cursor++;
    }

    if (*query_cursor == '\0') {
        return true;
    }

    size_t query_len = strlen(query);
    if (query_len == 0) {
        return true;
    }

    for (const char *start = title; *start; start++) {
        size_t i = 0;
        while (i < query_len && start[i] &&
               lower_ascii(start[i]) == lower_ascii(query[i])) {
            i++;
        }
        if (i == query_len) {
            return true;
        }
    }

    return false;
}

static char long_press_digit_for_key(const char *key)
{
    if (!key || key[1] != '\0') {
        return '\0';
    }

    switch (lower_ascii(key[0])) {
    case 'q': return '1';
    case 'w': return '2';
    case 'e': return '3';
    case 'r': return '4';
    case 't': return '5';
    case 'y': return '6';
    case 'u': return '7';
    case 'i': return '8';
    case 'o': return '9';
    case 'p': return '0';
    default: return '\0';
    }
}

static void apply_keyboard_mode(void)
{
    if (!s_keyboard) {
        return;
    }

    if (s_keyboard_mode == SEARCH_KEYBOARD_LOWER) {
        lv_buttonmatrix_set_map(s_keyboard, s_lower_map);
    } else if (s_keyboard_mode == SEARCH_KEYBOARD_UPPER) {
        lv_buttonmatrix_set_map(s_keyboard, s_upper_map);
    } else {
        lv_buttonmatrix_set_map(s_keyboard, s_symbol_map);
    }
}

static void switch_keyboard_mode(void)
{
    if (s_keyboard_mode == SEARCH_KEYBOARD_LOWER) {
        s_keyboard_mode = SEARCH_KEYBOARD_UPPER;
    } else if (s_keyboard_mode == SEARCH_KEYBOARD_UPPER) {
        s_keyboard_mode = SEARCH_KEYBOARD_SYMBOL;
    } else {
        s_keyboard_mode = SEARCH_KEYBOARD_LOWER;
    }

    apply_keyboard_mode();
}

static void result_event_cb(lv_event_t *event)
{
    if (lv_event_get_code(event) != LV_EVENT_CLICKED) {
        return;
    }

    search_result_item_t *item = lv_event_get_user_data(event);
    if (item) {
        ui_password_detail_set_entry(item->entry_index);
        ui_nav_push(serach_ui_show, ui_password_detail_show);
    }
}

static void add_result_row(size_t entry_index, size_t result_index)
{
    const kdbx_entry_t *entry = kdbx_get_entry(entry_index);
    if (!entry || result_index >= SEARCH_MAX_RESULTS) {
        return;
    }

    s_result_items[result_index].entry_index = entry_index;

    lv_obj_t *row = lv_obj_create(s_results_panel);
    lv_obj_remove_style_all(row);
    lv_obj_set_size(row, SEARCH_UI_WIDTH - 70, 64);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(row, result_event_cb, LV_EVENT_CLICKED, &s_result_items[result_index]);

    lv_obj_t *icon = lv_label_create(row);
    lv_label_set_text(icon, LV_SYMBOL_KEYBOARD);
    lv_obj_set_style_text_color(icon, lv_color_hex(0xFFA812), 0);
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_28, 0);
    lv_obj_align(icon, LV_ALIGN_LEFT_MID, 0, 0);

    lv_obj_t *title = lv_label_create(row);
    lv_label_set_text(title, entry->title);
    lv_obj_set_width(title, SEARCH_UI_WIDTH - 130);
    lv_label_set_long_mode(title, LV_LABEL_LONG_CLIP);
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_28, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 42, 0);
}

static void refresh_results(void)
{
    if (!s_results_panel || !s_query_textarea) {
        return;
    }

    lv_obj_clean(s_results_panel);

    const char *query = lv_textarea_get_text(s_query_textarea);
    size_t result_count = 0;
    size_t entry_count = kdbx_get_entry_count();
    for (size_t i = 0; i < entry_count && result_count < SEARCH_MAX_RESULTS; i++) {
        const kdbx_entry_t *entry = kdbx_get_entry(i);
        if (entry && title_matches_query(entry->title, query)) {
            add_result_row(i, result_count++);
        }
    }

    if (result_count == 0) {
        lv_obj_t *empty = lv_label_create(s_results_panel);
        lv_label_set_text(empty, "No results");
        lv_obj_set_style_text_color(empty, lv_color_hex(0x9EA3AD), 0);
        lv_obj_set_style_text_font(empty, &lv_font_montserrat_28, 0);
    }
}

static void keyboard_event_cb(lv_event_t *event)
{
    lv_event_code_t code = lv_event_get_code(event);
    lv_obj_t *keyboard = lv_event_get_target_obj(event);
    uint32_t button_id = lv_buttonmatrix_get_selected_button(keyboard);
    const char *key = lv_buttonmatrix_get_button_text(keyboard, button_id);
    if (!key || !s_query_textarea) {
        return;
    }

    if (code == LV_EVENT_LONG_PRESSED) {
        if (strcmp(key, LV_SYMBOL_OK) == 0) {
            switch_keyboard_mode();
            return;
        }

        char digit = long_press_digit_for_key(key);
        if (digit != '\0') {
            lv_textarea_add_char(s_query_textarea, digit);
            refresh_results();
        }
        return;
    }

    if (code != LV_EVENT_VALUE_CHANGED) {
        return;
    }

    if (strcmp(key, LV_SYMBOL_BACKSPACE) == 0) {
        lv_textarea_delete_char(s_query_textarea);
    } else if (strcmp(key, LV_SYMBOL_OK) == 0) {
        return;
    } else if (key[0] != '\0') {
        lv_textarea_add_text(s_query_textarea, key);
    }

    refresh_results();
}

void serach_ui_show(void)
{
    lv_obj_t *screen = lv_screen_active();
    lv_obj_clean(screen);
    ui_nav_enable_right_swipe(screen);
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x11141A), 0);
    lv_obj_set_style_pad_all(screen, 0, 0);

    lv_obj_t *title = lv_label_create(screen);
    lv_label_set_text(title, "Search");
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_28, 0);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 24, 34);

    s_query_textarea = lv_textarea_create(screen);
    lv_obj_set_size(s_query_textarea, SEARCH_UI_WIDTH - 48, 58);
    lv_obj_align(s_query_textarea, LV_ALIGN_TOP_MID, 0, 78);
    lv_textarea_set_one_line(s_query_textarea, true);
    lv_textarea_set_max_length(s_query_textarea, 48);
    lv_obj_set_style_bg_color(s_query_textarea, lv_color_hex(0x2B2C34), 0);
    lv_obj_set_style_border_color(s_query_textarea, lv_color_hex(0x31333C), 0);
    lv_obj_set_style_border_width(s_query_textarea, 1, 0);
    lv_obj_set_style_radius(s_query_textarea, 5, 0);
    lv_obj_set_style_text_color(s_query_textarea, lv_color_white(), 0);
    lv_obj_set_style_text_font(s_query_textarea, &lv_font_montserrat_24, 0);
    lv_obj_set_style_pad_left(s_query_textarea, 14, 0);
    lv_obj_set_style_pad_right(s_query_textarea, 14, 0);

    s_results_panel = lv_obj_create(screen);
    lv_obj_remove_style_all(s_results_panel);
    lv_obj_set_size(s_results_panel, SEARCH_UI_WIDTH - 48, 264);
    lv_obj_align(s_results_panel, LV_ALIGN_TOP_MID, 0, 150);
    lv_obj_set_style_bg_color(s_results_panel, lv_color_hex(0x292A32), 0);
    lv_obj_set_style_bg_opa(s_results_panel, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(s_results_panel, 6, 0);
    lv_obj_set_style_pad_all(s_results_panel, 14, 0);
    lv_obj_set_flex_flow(s_results_panel, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(s_results_panel, 4, 0);
    lv_obj_add_flag(s_results_panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(s_results_panel, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(s_results_panel, LV_SCROLLBAR_MODE_AUTO);

    s_keyboard = lv_buttonmatrix_create(screen);
    s_keyboard_mode = SEARCH_KEYBOARD_LOWER;
    apply_keyboard_mode();
    lv_obj_set_size(s_keyboard, SEARCH_UI_WIDTH - 12, 270);
    lv_obj_align(s_keyboard, LV_ALIGN_BOTTOM_MID, 0, -4);
    lv_obj_set_style_bg_opa(s_keyboard, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_keyboard, 0, 0);
    lv_obj_set_style_pad_all(s_keyboard, 0, 0);
    lv_obj_set_style_pad_row(s_keyboard, 4, 0);
    lv_obj_set_style_pad_column(s_keyboard, 4, 0);
    lv_obj_set_style_radius(s_keyboard, 3, LV_PART_ITEMS);
    lv_obj_set_style_bg_color(s_keyboard, lv_color_hex(0x292A32), LV_PART_ITEMS);
    lv_obj_set_style_bg_color(s_keyboard, lv_color_hex(0x3A3C46), LV_PART_ITEMS | LV_STATE_PRESSED);
    lv_obj_set_style_border_color(s_keyboard, lv_color_hex(0x1A1B22), LV_PART_ITEMS);
    lv_obj_set_style_border_width(s_keyboard, 1, LV_PART_ITEMS);
    lv_obj_set_style_text_color(s_keyboard, lv_color_white(), LV_PART_ITEMS);
    lv_obj_set_style_text_font(s_keyboard, &lv_font_montserrat_28, LV_PART_ITEMS);
    lv_obj_add_event_cb(s_keyboard, keyboard_event_cb, LV_EVENT_VALUE_CHANGED, NULL);
    lv_obj_add_event_cb(s_keyboard, keyboard_event_cb, LV_EVENT_LONG_PRESSED, NULL);

    refresh_results();
}
