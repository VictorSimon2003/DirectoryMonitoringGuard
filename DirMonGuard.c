#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <time.h>
#include <semaphore.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <sys/types.h>

struct FileInfo
{
    char filename[1024];
    off_t size;
    time_t last_modified;
};

char* createFullPath(const char *path, char *entryName)
{
    // Calculate the size required for the full path
    size_t path_len = strlen(path);
    size_t entryName_len = strlen(entryName);
    
    // Allocate memory for the full path
    char *full_path = malloc((path_len + entryName_len + 2) * sizeof(char)); // +2 for "/" and null terminator
    
    // Check if memory allocation was successful
    if (full_path == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    // Construct the full path
    sprintf(full_path, "%s/%s", path, entryName);
    
    return full_path;
}

int saveDirectoryData(const char *path, struct FileInfo *files, int *noFiles, char *isolatedFilesDirPath) 
{
    DIR *dir;
    struct dirent *entry;
    struct stat file_info;
    int noIsolatedFiles = 0;

    dir = opendir(path);
    if (dir == NULL) 
    {
        perror("Error in opening directory");
        return 1;
    }

    // Print directory name
    printf("-->Directory: %s\n", path);

    // Traverse directory
    while ((entry = readdir(dir)) != NULL) 
    {
        // Skip current and parent directories and .DS_Store(Mac OS)
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".DS_Store") == 0 )
            continue;

        // Get file info
        if (lstat(createFullPath(path, entry->d_name), &file_info) == -1) 
        {
            perror("Error getting file info");
            continue;
        }

        /* The file’s mode is 16 bits in length, with the four high-order bits representing the file’s type, 
        and the remaining lower 12 bits representing access permissions and their modifiers. */

        int mask = 4095;
        mask = file_info.st_mode & mask;
        //Check each files permissions and see if they might be corrupted 
        if(mask == 0) // Might be corrupted
        {
            // Create a pipe
            int pipefd[2];
            pid_t pid;

            if (pipe(pipefd) == -1) 
            {
                perror("pipe");
                exit(EXIT_FAILURE);
            }

            pid = fork();
            if(pid == -1) // Error
            {
                perror("Error in forking for corrupted file!");           
            }
            else if(pid == 0) // Child
            {
                // Close read end of the pipe
                close(pipefd[0]);

                printf("\nExecuting shell script for checking if file might be corrupted!\n");

                // Redirect stdout to the write end of the pipe
                dup2(pipefd[1], STDOUT_FILENO);

                // Close write end of the pipe
                close(pipefd[1]);

                execlp("./verify_for_malicious.sh", "./verify_for_malicious.sh", createFullPath(path, entry->d_name), NULL);                
                printf("Executing shell script failed!\n");
                exit(EXIT_FAILURE);
            }
            else // Parent 
            {
                wait(NULL);

                // Close write end of the pipe
                close(pipefd[1]);

                // Read from the read end of the pipe and print the output
                char buffer[100];
                ssize_t n = read(pipefd[0], buffer, sizeof(buffer));

                // Null-terminate the string
                buffer[n] = '\0';

                printf("%s\n", buffer);
                // File is not safe
                if(strcmp(buffer, "SAFE\n") != 0)
                {
                    // Rename file from oldname to newname
                    if (rename(createFullPath(path, entry->d_name), createFullPath(isolatedFilesDirPath, entry->d_name)) == 0)
                    {
                        printf("File moved successfully.\n\n");
                        noIsolatedFiles++; // Increment the count of isolated files
                        continue;
                    } 
                    else
                    {
                        perror("Error moved file");
                        exit(EXIT_FAILURE);
                    }
                }

                // Close read end of the pipe
                close(pipefd[0]); 
                
            }
            
        }
        
        // Add file info to array of files 
        strcpy(files[*noFiles].filename, entry->d_name);
        files[*noFiles].size = file_info.st_size;
        files[*noFiles].last_modified = file_info.st_mtime;

        (*noFiles)++; // Increment noFiles

        // Check if we have a directory
        if(S_ISDIR(file_info.st_mode))
        {
            noIsolatedFiles += saveDirectoryData(createFullPath(path, entry->d_name), files, noFiles, isolatedFilesDirPath); // Recursively call the function
        }
        else
        {
            printf("%s\n", entry->d_name);
        }
    }

    closedir(dir);
    return noIsolatedFiles;
}

bool hasChanges(int fd, struct FileInfo files[], int noFiles) 
{
    struct stat file_info;
    char prevSnapshot[1024];
    ssize_t bytes_read;
    int noIteratedFiles = 0;
    
    // Set cursor to the beginning
    lseek(fd, 0, SEEK_SET);
    // Check for changes in each file
    while ((bytes_read = read(fd, prevSnapshot, sizeof(prevSnapshot))) > 0)
    {
        // Get current file info
        if (stat(files[noIteratedFiles].filename, &file_info) == -1) 
        {
            //perror("Error in getting file info");
            continue;
        }

        // Create current Snapshot
        char currSnapshot[1024];
        sprintf(currSnapshot, "%s,%lld,%ld\n", files[noIteratedFiles].filename, files[noIteratedFiles].size, files[noIteratedFiles].last_modified);

        // Compare last snapshot with current
        if (strncmp(currSnapshot, prevSnapshot, bytes_read) != 0) 
        {
            // We need to replace current file Snapshot with new one
            return true;
        }
        noIteratedFiles++;
    }

    if (noIteratedFiles != noFiles || bytes_read == -1) return true;

    return false;
}

void createSnapshot(const char *path, struct FileInfo files[], int noFiles, int directoryNumber)
{
    int fd = -1;

    char newPartialDirName[50];
    sprintf(newPartialDirName, "%s%d%s", "DirSnapshot", directoryNumber, ".txt");
    // Open Snapshot file if there is one
    fd = open(createFullPath(path, newPartialDirName), O_RDWR);

    // First Snapshot yet or current Snapshot is different from previous one
    if(fd == -1 || hasChanges(fd, files, noFiles) == true)
    {
        close(fd);
        // Truncate current File
        fd = open(createFullPath(path, newPartialDirName),  O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        // Traverse the files
        for(int i = 0; i < noFiles; i++)
        {
            dprintf(fd, "Name: %s, Size: %lld, Last modified: %ld\n", files[i].filename, files[i].size, files[i].last_modified);
        }
    }

    // There is an existing Snapshot that matches the current one so do nothing
    
    close(fd);
}

int main(int argc, char *argv[]) 
{
    // Check if directory path is provided
    if (argc < 6 || strcmp(argv[1], "-o") != 0 || strcmp(argv[3], "-s") != 0)
    {
        printf("Invalid arguments! Correct input: ./program_exe -o output_dir -s output_isolated_dir dir1 dir2 dir3 dir4...");
        exit(EXIT_FAILURE);
    }

    // argv[2] = Snapshot dir
    DIR *snapshotDir;
    snapshotDir = opendir(argv[2]);

    if(snapshotDir == NULL)
    {
        perror("Failed to open Snapshot directory");
        return EXIT_FAILURE;
    }

    // Prepare for storing process information
    int childId[argc - 5];
    int childStatus[argc - 5];
    int noFiles = 0;
    struct FileInfo files[100];
    dispatch_semaphore_t semaphore;
    semaphore = dispatch_semaphore_create(1);

    int maliciousFileCount[argc - 5];
    int pipefd[argc - 5][2]; // Create an array of pipes for each child process
    for (int i = 0; i < argc - 5; i++)
    {
        if (pipe(pipefd[i]) == -1)
        {
            perror("pipe");
            exit(EXIT_FAILURE);
        }
    }

    // Start all the processes 
    for(int i = 5; i < argc; i++)
    {
        childId[i - 5] = fork(); 
        maliciousFileCount[i - 5] = 0;
        if(childId[i - 5] == -1)
        {
            printf("Error creating child process %d", i + 1);
            exit(EXIT_FAILURE);
        }  
    }

    // Child
    for(int i = 5; i < argc; i++)
    {
        if(childId[i - 5] == -1)
        {
            printf("Process creation failed for Directory %d", i - 4);
            exit(EXIT_FAILURE); 
        }
        else if(childId[i - 5] == 0)
        {
            // Close the read end of the pipe
            close(pipefd[i - 5][0]);

            // Make sure there is no race condition
            dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

            // Traverse on current path everything
            maliciousFileCount[i - 5] = saveDirectoryData(argv[i], files, &noFiles, argv[4]);

            // Write maliciousFileCount to the pipe
            if (write(pipefd[i - 5][1], &maliciousFileCount[i - 5], sizeof(int)) == -1) 
            {
                perror("write");
                exit(EXIT_FAILURE);
            }

            // Create Snapshot
            createSnapshot(argv[2], files, noFiles, i - 4);
            printf("Snapshot for Directory %d updated successfully.\n\n", i - 4);

            //Allow other processes to begin their work
            dispatch_semaphore_signal(semaphore);
            // Close the write end of the pipe
            close(pipefd[i - 5][1]);
            exit(EXIT_SUCCESS); // Child process exits successfully

        }
    }
    
    // Delete semaphore
    dispatch_release(semaphore);
    
    // Parent
      
    // Wait for all children
    for(int i = 5; i < argc; i++)
    {
        wait(&childStatus[i - 5]);

        if (WIFEXITED(childStatus[i - 5]))
        {
            // Close the write end of the pipe 
            close(pipefd[i - 5][1]);
            int count;
            if (read(pipefd[i - 5][0], &count, sizeof(int)) == -1) 
            {
                perror("read");
                exit(EXIT_FAILURE);
            }

            printf("Child Process %d terminated with PID %d and %d files with potential danger.\n", i - 4, childId[i - 5], count);

        } else 
        {
            printf("Child Process %d terminated abnormally.\n", i - 4);
        }

        // Close the read end of the pipe
        close(pipefd[i - 5][0]);
    }
    
    // Check for changes
    for(int i = 5; i < argc; i++)
    {
        int fd = -1;
        // Open the snapshot file and start checking for changes
            char newPartialDirName[50];
            sprintf(newPartialDirName, "%s%d%s", "DirSnapshot", i - 4, ".txt");
            fd = open(createFullPath(argv[2], newPartialDirName), O_RDONLY);
            if (fd == -1) 
            {
                perror("Error opening Snapshot file for checking changes!");
                exit(EXIT_FAILURE);
            }

            // Call hasChanges with the opened file
            if (hasChanges(fd, files, noFiles) == true) 
            {
                printf("Changes detected in %s\n", argv[i]);
            } 
            
            close(fd); 
    }
        
    exit(EXIT_SUCCESS);
}
