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
In the current state of the program for checkpoint A, only public messages are supported. A client can send a public message by typing directly into the command line after connecting to the server via the setup procedure described above. This message will be parsed and stored as a public message with the generic sender name as "client." The user can only send a message of maximum length 512. If the message exceeds this length, it will not be accepted and the program will exit and flush the input. More on error handling is described below.
- Error Handling \
This chat server also employs various helper functions in the ``ui.c`` file to check, clean, and parse user input from the command line. These functions include `void flush_stdin()` to clear input when exiting, `char *remove_leading_space()` and `void remove_trailing_space()` to trim messages, and `int new_line_count()` to ensure that one command is being inputted and processes at a time.

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

### Database
For checkpoint A, we created a single sqlite table, *chat.db*,  to store public messages. This database is initialized in the `server.c` file in the `static int server_state_init()` function. A reference to the database, called *db*, is stored in the ``server_state`` mentioned above. The table has the following columns: id, timestamp, msg_len, sender, and msg_type. Insertion and reads of the database occur in the ``worker.c`` file. The `static int handle_s2w_notification()` function runs a SELECT query on the database with a filter for an id greater than the last read id. The `static int execute_request()` function inserts messages into the database using the `sqlite3_mprintf()` function to compile the INSERT query and `sqlite3_exec()` to execute the query.
## Security Overview
### Basic Techniques
First, all user input will be sanitized appropriately. Sanitization includes verifying the data follows the expected structure, verifying the data values are within reasonable range, and immeditaely rejecting unsuitable inputs. Some of this functionality is already present in the checkpoint A code. For example, user input has a set length limit, empty string are rejected, and multiple new lines are rejected. \
Also, the system will be secured with client and server authentication. We will use the *OpenSSL* library to ensure secure communication over computer networks and the *OpenSLL/crypto* library to generate keys for authentication. The server will have a self-signed certificate and the clients will have certificates signed by the server. 
### Cryptograph Applied to Each Message Type
- Exit \
This command does not use any crytography. All users can exit at any point. However, this command is sanitized using set input lengths and removing excess whitespace.
- Login \
This command will hash the password and compare it to the stored password in the *users* database table.
- Private Message \
This command will include a digital signature of the sender. This sigature will be generated with a ``EVP_MD_CTX`` context using the `EVP_MD_CTX_create` function in the OpenSLL library.
- Public Message \
This command will include a digital signature of the sender. This sigature will be generated with a ``EVP_MD_CTX`` context using the `EVP_MD_CTX_create` function in the OpenSLL library.
- Register \
This command will generate a certificate signing request and private key for the client and stored a salted hashed password in the *users* database table. The certificate and private key will be generated through the OpenSLL libary.
- Users \
This command will check if the user is  authenticated. If the user is not an authenticated client, the program will exit and display an appropriate error. To verify if the user has proper access permission, we will use the function `static int is_logged_in()` in the *util.c* file.
### Key Distribution
The server and client keys will be stored on the disk in the respective */serverkeys* and */clientkeys* directories. All other data will be stored in memory. \
In order to store and distribute client and server keys, we will use a TTP to identify all users and link them with their public key. This TTP will operate as a python3 script and will retrieve keys from the respective directories. The TTP will receieve a username a return a public key to an authenticated user who requests the information.
### Protections Against Described Threat Model
The threat model and proposed solutions are as follows:
- Determine at which addresses all clients and the server are running. \
We will be using a certification authority to link and distribute keys to authenticate users and the server. The process of key distribution is described above.
- Read, modify, inject, and/or block data sent over any network connection between a client and the server. \
Reading (the actual) data will be prohibited by encrypting all data sent in either direction between client and server.
Modifying data will be detected by using data blocks, where each successive block contains the hash of the previous one. Therefore, a modified block will be detected, since the hash won't be the same.
Injecting data will also be detected by the block model, as for a good hash function, there is no way for Mallory to find a message with the same hash as the one that has been sent.
Similarly, blocking data will be detected, since then there will be arriving blocks that contain hashes of previous blocks, who we have never received.
- Establish a connection with any client or the server, spoofing her network address to any possible value. \
Since Mallory has no acess to the client's password, they will be unable to login to the client's account.
- Implement a malicious client to attack either the server or other clients by sending specially crafted data.\
All our commands use sanitization and authorization. Additionally, commands that interact with the database implement escaping. Specfially, the username, password, and messsages sent to the database are prepared for quering via the `sqlite3_bind()` command. This protects against sql injection attacks.
- Implement a malicious server and get clients to connect to it instead of the intended server, to attack clients by sending specially crafted data.\
Our server has a self-signed certificate to verify its identity. (The clients will be supplied with the information which certificate to trust in production)
- Perform these actions any number of times, possibly simultaneously.\
The actions by Mallory will be independently rejected or detected. Any repetition of the actions will not break the encryption.