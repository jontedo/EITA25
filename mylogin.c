/*
 * Shows user info from local pwfile.
 *
 * Usage: userinfo username
 */
#include <stdio.h>

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h" /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)

int print_info(const char *username)
{
    struct pwdb_passwd *p = pwdb_getpwnam(username);
    if (p != NULL)
    {
        printf("Name: %s\n", p->pw_name);
        printf("Passwd: %s\n", p->pw_passwd);
        printf("Uid: %u\n", p->pw_uid);
        printf("Gid: %u\n", p->pw_gid);
        printf("Real name: %s\n", p->pw_gecos);
        printf("Home dir: %s\n", p->pw_dir);
        printf("Shell: %s\n", p->pw_shell);
        return 0;
    }
    else
    {
        return NOUSER;
    }
}

void read_username(char *username)
{
    printf("login: ");
    fgets(username, USERNAME_SIZE, stdin);

    /* remove the newline included by getline() */
    username[strlen(username) - 1] = '\0';
}

int checkPassword(char username[], char password[])
{
    struct pwdb_passwd *pwd = pwdb_getpwnam(username);

    if (pwd == NULL)
    {
        printf("ERROR Did not find user.\n");
        return 0;
    }

    int SALT_SIZE = 2;
    char salt[SALT_SIZE];
    strncpy(salt, pwd->pw_passwd, SALT_SIZE);

    return strcmp(pwd->pw_passwd, crypt(password, salt)) == 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    char username[USERNAME_SIZE];
    char *password;

    while (1)
    {
        read_username(username);
        password = getpass("Password: ");

        if (checkPassword(username, password))
        {
            printf("User authenticated successfully\n");
            return 0;
        }
        else
        {
            printf("Unknown user or incorrect password.\n");
        }
    }

    /*
     * Write "login: " and read user input. Copies the username to the
     * username variable.

    read_username(username);

       Show user info from our local pwfile.
    if (print_info(username) == NOUSER) {
        // if there are no user with that usename...
        printf("\nFound no user with name: %s\n", username);
        return 0;
    }*/
}
