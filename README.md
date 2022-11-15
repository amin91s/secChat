# SecChat Project

## Setup
To run the code stored in this repository, first navigate to the appropriate repository directory. Then, run the following code with the TCP port number of your choosing.
```
make all
./server 8080
./client localhost 8080
```
## Code Overview
### Chat Basics 
- Data Flow \
  The general flow of data starts when a user input a command into the command line. This is processed in the ``client.c`` file, passed to the ``worker.c`` to communicate with the server and returned to the appropriate clients via their workers. All of the users/clients have corresponding workers that handle communication to and from the server on behalf of the client.
- Messages \
  There are two types of messages, public and private, stored in a singular database by the server. A client can send a public message by typing directly into the command line after connecting to the server via the setup procedure described above. This message will be parsed and stored as a public message with the generic sender name as "client." The client can only send a message of maximum length 512. If the message exceeds this length, it will not be accepted and the program will exit and flush the input. More on error handling is described below. A client can also sender a private message to another registered user of the SecChat application by typing "@username" before the message with the specified username of the receipient. The receipient of the message is not required to be logged on but is required to be a registered user. Additionally, the size restriction of 512 characters including the null terminator is similarly enforced.
- Error Handling \
  This chat server also employs various helper functions in the ``ui.c`` file to check, clean, and parse user input from the command line. These functions include `void flush_stdin()` to clear input when exiting, `char *remove_leading_space()` and `void remove_trailing_space()` to trim messages, and `int new_line_count()` to ensure that one command is being inputted and processes at a time.
- Usage Information \
  The application also supports usage statements all commands that require parameters. For example, if a user were to try and start the server without specifying a port number, the application would print `usage: server port` to stdout to indicate to the user that a port is required after the server command.
### Framework and Structures
The main structures used to store and pass data within this application are in the ``api.h``, ``cmd.h``, ``ui.h``, and ``server.c`` files. Additionally, the ``cmd.h`` file holds the enum for the various command types. Each of the structures along with their usage is described below:
- *``struct api_msg``*:
  This is the main structure that holds a message. The key field within this struct is ``enum cmd_type type`` which is further explain below. However, in summary, this field describes which of the 6 different message types the structure is representing. Besides the type field, ``api_msg`` also holds user and message buffers of a predefined max length, a message length, and a char[] holding the timestamp of the message. The timestamp is acquired from the builtin ``time.h``.
- *`struct api_state`*:
  This struct is used to pass information between clients and workers. It only contains a int fd and thus does not need memory allocated.
- *`cmd_type`*: This enum holds the 6 different messages possible in the chat server.
  - ``CMD_EXIT``:
  - ``CMD_LOGIN``
  - ``CMD_PRIVATE_MSG``
  - ``CMD_PUBLIC_MSG``
  - ``CMD_REGISTER``
  - ``CMD_USERS``
- *`struct ui_state`*: This structure stores the command arguments received from the user interface. It contains a type field, message field, and timestamp variable.
- *`struct server_child_state`*: This struture holds a file descriptor to the child's specific worker and an integer to indicate wheter a notication is pending.
- *`struct server_state`*: This structure holds a socket file descriptor, an array of ``sever_state_children`` capped at the max size of 16, a count of current children and a reference to the sqlite database.
- *`struct worker_state`*: This structure holds all the information to communicate between the client and server and contains references to the last read and last inserted message. These fields keep track of which messages need to be broadcasted when a user logs in.

### Database
The database has a sqlite table to store all messages and another sqlite table to store all users. Both tables reside in the *chat.db* file. This database is initialized in the `server.c` file in the `static int server_state_init()` function. \

For the messages table, a reference to the table, called *db*, is stored in the ``server_state`` mentioned above. The table has the following columns: id, timestamp, msg text, msg_len, sender, and msg_type. Insertion and reads of the database occur in the ``worker.c`` file. The `static int handle_s2w_notification()` function prepares and binds the SELECT query on the database with a filter for an id greater than the last read id. The `static int execute_request()` function inserts messages into the database using the `sqlite3_prepare_v2(()` function to run the INSERT INTO query. Private messages follow the same structure and only differ in the message type field.

 