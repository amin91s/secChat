#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "ui.h"
#include "util.h"
/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state)
{
    assert(state);
    /* free ui_state */
    free(state->message);
    memset(state, 0, sizeof(*state));
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state)
{
    assert(state);
    /* initialize ui_state */
    state->message = (char *)calloc(MAX_MESSAGE_LENGTH+MAX_USR_LENGTH+2, sizeof(char));
}

/* Helper functions to deal with user input */

void flush_stdin(void)
{
    int c;
    while ((c = getchar()) != EOF && c != '\n');
}

char *remove_leading_space(char *buffer, size_t len)
{
    char *p = buffer, *p_end = buffer + len;
    while (p < p_end && isspace(*p) && p[0] != '\n')
        p++;
    return p;
}

int new_line_count(char *buffer)
{
    int i;
    for (i = 0; buffer[i]; buffer[i] == '\n' ? i++ : *buffer++);
    return i;
}

void remove_trailing_space(char *buffer, size_t len)
{
    char *endPtr = buffer + len - 1;
    while (endPtr > buffer && isspace(*endPtr))
        endPtr--;
    endPtr[1] = '\n';
    endPtr[2] = '\0';
}


int get_credential(char *temp,struct ui_state *ui){
    int usrLen=0;
    memset(ui->username,'\0',MAX_USR_LENGTH+1);
    memset(ui->password,'\0',MAX_PASS_LENGTH+1);

    while(!isspace(temp[usrLen])){
        ui->username[usrLen] = temp[usrLen];
        usrLen++;
        if(usrLen > MAX_USR_LENGTH){
            printf("error: username exceeded maximum length\n");
            return 0;
        }
    }
    if(usrLen < MIN_USR_LENGTH || usrLen > MAX_USR_LENGTH){
        printf("error: invalid username length\n");
        return 0;
    }
    temp+=usrLen;
    temp = remove_leading_space(temp, strlen(temp));
    if (isspace(*temp)) {
        printf("error: invalid command format\n");
        return 0;
    }

    int passLen=0;

    while(!isspace(temp[passLen])){
        ui->password[passLen] = temp[passLen];
        passLen++;
        if(passLen > MAX_PASS_LENGTH){
            printf("error: password exceeded maximum length\n");
            return 0;
        }
    }

    temp+=passLen;
    temp = remove_leading_space(temp, strlen(temp));
    if (temp[0] != '\n'){
        printf("error: invalid command format\n");
        return 0;
    }
    if(passLen < MIN_PASS_LENGTH || passLen > MAX_PASS_LENGTH){
        printf("error: invalid password length\n");
        return 0;
    }
    //successful
    return 1;
}