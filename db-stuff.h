//
// Created by Amin Soleimani on 30/11/2021.
//

#ifndef _DB_STUFF_H_
#define _DB_STUFF_H_




int register_user(sqlite3 *db, char *username, char *hash, char *salt){
    int r = SQLITE_OK;
    sqlite3_stmt *stmt = NULL;
    sqlite3_open("chat.db", &db);
    if(r != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 2000 );

    char *sql = "insert into users (username, salt, hash) values (@username, @salt, @hash);";
    if((r = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) goto cleanup;
    if((r = sqlite3_bind_text(stmt, 1,username ,-1 , SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
    if((r = sqlite3_bind_text(stmt, 2,salt ,-1 , SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
    if((r = sqlite3_bind_text(stmt, 3,hash ,-1 , SQLITE_STATIC)) != SQLITE_OK) goto cleanup;

    r = sqlite3_step(stmt);
    cleanup:
    if (r != SQLITE_OK && r != SQLITE_DONE && r != SQLITE_CONSTRAINT)
        fprintf(stderr, "database error: %s\n",sqlite3_errmsg(db));
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return r;
}
//returns 0 if username is not in db, 1 otherwise
int get_credentials(sqlite3 *db, char *username, char *hash, char *salt){
    int r = sqlite3_open("chat.db", &db);
    if(r != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 2000 );
    sqlite3_stmt *stmt = NULL;
    int res=-1;
    char *sql = "select username,salt,hash,status from users where username = @username;";
    if((r = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) goto cleanup;

    if((r = sqlite3_bind_text(stmt, 1,username ,-1 , SQLITE_STATIC)) != SQLITE_OK) goto cleanup;

    r = sqlite3_step(stmt);

    if(r == SQLITE_ROW){
        //user exists
        strncpy(salt,(char*)sqlite3_column_text(stmt, 1),MAX_SALT_LENGTH);
        strncpy(hash,(char*)sqlite3_column_text(stmt, 2),MAX_HASH_LENGTH);
        res = 1;
    } else if(r == SQLITE_DONE){
        res = 0;
    }
    cleanup:
    if (r != SQLITE_OK && r != SQLITE_DONE && r != SQLITE_ROW)
        fprintf(stderr, "database error: %s\n",sqlite3_errmsg(db));
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return res;
}

int insert_msg(sqlite3 *db,char *sender,char *receiver, char *message, size_t encrypted_msg_len, int msg_type){
    int r = sqlite3_open("chat.db", &db);
    if(r != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 2000 );
    sqlite3_stmt *stmt = NULL;
    char *sql = NULL;
    if(msg_type == CMD_PUBLIC_MSG) {
        sql = "insert into msg (timestamp, msg, sender, receiver,msg_type) values (datetime('now'),?1,?2,?3,?4);";
    } else{
        sql = "insert into msg (timestamp, msg, sender, receiver,msg_type) values (datetime('now'),?1,?2,(select username from users where username = ?3),?4);";
    }

    if((r = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) goto cleanup;

    //bind as text for testing. change it later
    //r+= sqlite3_bind_blob(stmt, 1,message, encrypted_msg_len, SQLITE_STATIC);
    if((r= sqlite3_bind_text(stmt, 1, message, -1, SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
    if((r= sqlite3_bind_text(stmt, 2, sender, -1, SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
    if((r= sqlite3_bind_text(stmt, 3, receiver, -1, SQLITE_STATIC)) != SQLITE_OK) goto cleanup;
    if((r= sqlite3_bind_int(stmt, 4, msg_type)) != SQLITE_OK) goto cleanup;

    r = sqlite3_step(stmt);
    cleanup:
    if (r != SQLITE_OK && r != SQLITE_DONE && r != SQLITE_CONSTRAINT)
        fprintf(stderr, "database error: %s\n", sqlite3_errmsg(db));
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return r;
}

int get_users(sqlite3 *db, struct api_msg *msg){
    int r = sqlite3_open("chat.db", &db);
    if(r != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 2000 );
    sqlite3_stmt *stmt = NULL;
    char *sql = "SELECT username from users where status = 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK){
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            strncpy(msg->users.users[msg->users.num_users], (char *)sqlite3_column_text(stmt, 0), MAX_USR_LENGTH);
            msg->users.num_users++;
        }
    } else {

        if(stmt) sqlite3_finalize(stmt);
        if(db) sqlite3_close(db);
        fprintf(stderr, "Error binding statement: %s \n", sqlite3_errmsg(db));
        return -1;
    }
    if(stmt)
        sqlite3_finalize(stmt);
    if(db)
        sqlite3_close(db);
    return 0;
}
int set_user_status(sqlite3 *db, char *username, int status){
    int r = sqlite3_open("chat.db", &db);
    if(r != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 2000 );

    sqlite3_stmt *stmt = NULL;
    char *sql = "UPDATE users SET status=? where username=?;";


    if((r = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) goto cleanup;
    if((r= sqlite3_bind_int(stmt, 1,status)) != SQLITE_OK) goto cleanup;
    if((r= sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC)) != SQLITE_OK) goto cleanup;

    r = sqlite3_step(stmt);
    cleanup:
    if (r != SQLITE_OK && r != SQLITE_DONE)
        fprintf(stderr, "database error: %s\n",sqlite3_errmsg(db));
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return r;
}



#endif
