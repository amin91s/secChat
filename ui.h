#ifndef _UI_H_
#define _UI_H_

#include "cmd.h"
#include "api.h"

struct ui_state
{
  /* TODO add fields to store the command arguments */
  enum cmd_type cmd;
  char *message;
  char username[MAX_USR_LENGTH+1];
  char password[MAX_PASS_LENGTH+1];
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

/* TODO add UI calls interact with user on stdin/stdout */
void flush_stdin(void);
char *remove_leading_space(char *buffer, size_t len);
void remove_trailing_space(char *buffer, size_t len);

int new_line_count(char *buffer);
int get_credential(char *temp,struct ui_state *ui);


#endif /* defined(_UI_H_) */
