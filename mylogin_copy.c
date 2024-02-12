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
#define LOCKED (-2)
#define MAX_ATTEMPT (5)
#define SALT_SIZE (2)
#define NOTIFY_CHANGE_PASS (2)

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
    char salt[SALT_SIZE];

    if (pwd == NULL)
    {
        return NOUSER;
    }

    if (pwd->pw_failed >= MAX_ATTEMPT)
    {
        return LOCKED;
    }

    strncpy(salt, pwd->pw_passwd, SALT_SIZE);

    int status = strcmp(pwd->pw_passwd, crypt(password, salt)) == 0 ? 1 : 0;

    if (status == 1)
    {
        pwd->pw_failed = 0;
        pwd->pw_age++;
        if (pwd->pw_age >= NOTIFY_CHANGE_PASS)
        {
            printf("You should probably change your password now...\n");
        }
    }
    else
    {
        pwd->pw_failed++;
    }

    pwdb_update_user(pwd);

    return status;
}

int main(int argc, char **argv)
{
    char username[USERNAME_SIZE];
    char *password;
    int login_attempts = 0;

    while (login_attempts < MAX_ATTEMPT)
    {
        read_username(username);
        password = getpass("Password: ");
        int status = checkPassword(username, password);

        if (status == 1)
        {
            printf("User authenticated successfully\n");
            return 0;
        }
        if (status == LOCKED)
        {
            printf("Too many login attempts, account is now LOCKED");
            break;
        }

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
