#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h> 
#include <acl/libacl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

int showPermissions(acl_t acl, char* filename);
int createRule(acl_t *aclt, char* filename);
int deleteRule(acl_t *aclt, char* filename);

int main (int argc, char *argv[]) {
    printf("Programm 9 started!\n");
    int res = 0;
    printf("File: %s\n", argv[1]);
    
    acl_t acl = acl_get_file(argv[1], ACL_TYPE_ACCESS);
    if(acl == NULL){
        perror("acl_get_file");
        exit(1);
    }
    int ch = 1;
    while(ch){
        printf("Select action: \n1.Show ACL\n2.Delete Rule\n3.Create Rule\n0.Exit\nSelect: ");
        scanf("%d", &ch);
        switch(ch){
            case 1:
                showPermissions(acl, argv[1]);
                break;
            case 2: 
                res = deleteRule(&acl, argv[1]);
                if(res == -1){
                    printf("deleting error\n");
                    return -1;
                }
                break;
            case 3:
                res = createRule(&acl, argv[1]);
                if(res == -1){
                    printf("create Rule error\n");
                    // return -1;
                } else {
                    printf("new rules: \n");
                    showPermissions(acl, argv[1]);
                }
                break;
            case 0:
                res = acl_free(acl);
                if(res != 0){
                    perror("acl_free");
                }
                printf("Programm 9 finished!\n");
                return 0;
            default:
                printf("???");
                break;
        }        
    }
    
}

int createRule(acl_t* aclt, char* filename){
    acl_t acl = *aclt;
    acl_entry_t newEntry;
    acl_permset_t newPermset;
    acl_tag_t ACL_TYPES[5] = {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_OTHER};
    int res = acl_create_entry(&acl, &newEntry);
    if(res == -1){
        perror("acl_create_entry");
        return -1;
    }
    printf("1.User_OBJ\n2.User\n3.Group_OBJ\n4.Group\n5.Other\n");
    printf("Which type: ");
    int ch;
    scanf("%d", &ch);
    res = acl_set_tag_type(newEntry, ACL_TYPES[ch-1]);
    if(res == -1){
        perror("acl_set_tag_type");
        return -1;
    }
    if(ch == 2 || ch == 4){
        printf("Input ID: ");
        int buf;
        scanf("%d", &buf);
        printf("Your ID: %d\n", buf);
        res = acl_set_qualifier(newEntry, &buf);
        if(res == -1){
            perror("acl_set_qualifier");
            return -1;
        }
    }
    res = acl_get_permset(newEntry, &newPermset);
    if(res == -1){
        perror("acl_get_permset");
        return -1;
    }
    res = acl_clear_perms(newPermset);
    if(res == -1){
        perror("acl_clear_perms");
        return -1;
    }
    res = acl_set_permset(newEntry, newPermset);
    if(res == -1){
        perror("acl_set_permset");
        return -1;
    }
    res = acl_calc_mask(&acl);
    if(res == -1){
        perror("acl_calc_mask");
        return -1;
    }
    res = acl_valid(acl);
    if(res == -1){
        perror("acl_valid");
        return -1;
    }
    return acl_set_file(filename, ACL_TYPE_ACCESS, acl);
}

int deleteRule(acl_t* aclt, char* filename){
    acl_t acl = *aclt;
    acl_tag_t ACL_TYPES[5] = {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_OTHER};
    printf("Select delete rule:\n1.User_OBJ\n2.User (with name or ID)\n3.Group_OBJ\n4.Group (with name or ID)\n5.Other\n");
    int ch, id, res;
    char name[255];
    scanf("%d", &ch);
    acl_tag_t selected = ACL_TYPES[ch-1];
    if(ch == 2 || ch == 4){
        printf("Select input: 1 = name, 2 = ID\n");
        scanf("%d", &ch);
        if(ch == 1){
            printf("Input rule name: ");
            scanf("%s", name);
        } else {
            printf("Input rule ID: ");
            scanf("%d", &id);
        }
    }
    int entryId = ACL_FIRST_ENTRY;
    acl_entry_t entry;
    acl_tag_t tag;
    while(1){
        int res = acl_get_entry(acl, entryId, &entry);
        if(res != 1){
            if(res == -1){
                perror("acl_get_entry");
                exit(1);
            }
            printf("Rule doesnt exist\n");
            return 0;
            break;
        }
        res = acl_get_tag_type(entry, &tag);
        if(res == -1){
            perror("acl_get_tag_type");
            exit(1);
        }
        if(tag == selected){
            if(tag != ACL_USER && tag != ACL_GROUP){
                res = acl_delete_entry(acl, entry);
                if(res == -1){
                    perror("acl_delete_entry");
                    return -1;
                }
                res = acl_valid(acl);
                if(res == -1){
                    perror("acl_valid");
                    return -1;
                }
                res = acl_set_file(filename, ACL_TYPE_ACCESS, acl);
                if(res == -1){
                    perror("acl_set_file");
                    return -1;
                }
                break;
            } else {
                if(tag == ACL_USER){
                    uid_t* uidp = acl_get_qualifier(entry);
                    if(uidp == NULL){
                        perror("acl_get_quilifier");
                        return -1;
                    }
                    if(ch == 1){
                        struct passwd* pwd;
                        pwd = getpwuid(*uidp);
                        if(pwd != NULL){
                            char* pwName = pwd->pw_name;
                            if(strcmp(name, pwName) == 0){
                                res = acl_delete_entry(acl, entry);
                                if(res == -1){
                                    perror("acl_delete_entry");
                                    return -1;
                                }
                                res = acl_valid(acl);
                                if(res == -1){
                                    perror("acl_valid");
                                    return -1;
                                }
                                res = acl_set_file(filename, ACL_TYPE_ACCESS, acl);
                                if(res == -1){
                                    perror("acl_set_file");
                                    return -1;
                                }
                                break;
                            }
                        }
                    } else {
                        if(*uidp == id){
                            res = acl_delete_entry(acl, entry);
                            if(res == -1){
                                perror("acl_delete_entry");
                                return -1;
                            }
                            res = acl_valid(acl);
                            if(res == -1){
                                perror("acl_valid");
                                return -1;
                            }
                            res = acl_set_file(filename, ACL_TYPE_ACCESS, acl);
                            if(res == -1){
                                perror("acl_set_file");
                                return -1;
                            }
                            break;
                        }
                    }
                } else if(tag == ACL_GROUP){
                    gid_t* gidp = acl_get_qualifier(entry);
                    if(gidp == NULL){
                        perror("acl_get_quilifier");
                        return -1;
                    }
                    if(ch == 1){
                        struct group* grp;
                        grp = getgrgid(*gidp);
                        if(grp != NULL){
                            char* gwName = grp->gr_name;
                            if(strcmp(gwName, name) == 0){
                                res = acl_delete_entry(acl, entry);
                                if(res == -1){
                                    perror("acl_delete_entry");
                                    return -1;
                                }
                                res = acl_valid(acl);
                                if(res == -1){
                                    perror("acl_valid");
                                    return -1;
                                }
                                res = acl_set_file(filename, ACL_TYPE_ACCESS, acl);
                                if(res == -1){
                                    perror("acl_set_file");
                                    return -1;
                                }
                                break;
                            }
                        }
                    } else {
                        if(*gidp == id){
                            res = acl_delete_entry(acl, entry);
                            if(res == -1){
                                perror("acl_delete_entry");
                                return -1;
                            }
                            res = acl_valid(acl);
                            if(res == -1){
                                perror("acl_valid");
                                return -1;
                            }
                            res = acl_set_file(filename, ACL_TYPE_ACCESS, acl);
                            if(res == -1){
                                perror("acl_set_file");
                                return -1;
                            }
                            break;
                        }
                    }
                }
            }    
        }
        entryId = ACL_NEXT_ENTRY;
    }
    return 0;
}

int showPermissions(acl_t acl, char* filename){
    acl_type_t type;
    acl_entry_t entry;
    acl_tag_t tag;
    uid_t *uidp;
    gid_t *gidp;
    acl_permset_t permset;
    int entryId = ACL_FIRST_ENTRY;
    while(1){
        int res = acl_get_entry(acl, entryId, &entry);
        if(res != 1){
            if(res == -1){
                perror("acl_get_entry");
                exit(1);
            }
            break;
        }
        res = acl_get_tag_type(entry, &tag);
        if(res == -1){
            perror("acl_get_tag_type");
            exit(1);
        }
        printf("%s\n",      (tag == ACL_USER_OBJ) ?  "user_obj" :
                            (tag == ACL_USER) ?      "user" :
                            (tag == ACL_GROUP_OBJ) ? "group_obj" :
                            (tag == ACL_GROUP) ?     "group" :
                            (tag == ACL_MASK) ?      "mask" :
                            (tag == ACL_OTHER) ?     "other" : "???");
        if(tag == ACL_USER){
            uidp = acl_get_qualifier(entry);
            if(uidp == NULL){
                perror("acl_get_quilifier");
                exit(1);
            }
            struct passwd* pwd;
            pwd = getpwuid(*uidp);
            if(pwd != NULL){
                char* name = pwd->pw_name;
                if(name)printf("Name: %s\n", name);
                printf("Id: %d\n", *uidp);
            } else {
                printf("Id: %d\n", *uidp);
            }
            // res = acl_free(uidp);
            // if(res == -1)perror("acl_free");
        } 
        if (tag == ACL_GROUP) {
            gidp = acl_get_qualifier(entry);
            if(gidp == NULL){
                perror("acl_get_quilifier");
                exit(1);
            }
            struct group* grp;
            grp = getgrgid(*gidp);
            if(grp != NULL){
                char* name = grp->gr_name;
                if(name)printf("Group Name: %s\n", name);
                printf("Id: %d\n", *gidp);
            } else {
                printf("Id: %d\n", *gidp);
            }
            // res = acl_free(gidp);
            // if(res == -1)perror("acl_free");
        }

        struct stat buf;
        // res = stat(filename, &buf);
        // if(res == -1)perror("stat");
        // else printf("UId: %d\nGId: %d\n", buf.st_uid, buf.st_gid);                
        res = acl_get_permset(entry, &permset);
        if(res == -1)perror("acl_get_perm");
        printf("Permission: ");
        int perms[3] = {ACL_READ, ACL_WRITE, ACL_EXECUTE};
        char permsSymbols[3] = {'r', 'w', 'x'};
        for(int i = 0; i < 3; i++){
            int permValue = acl_get_perm(permset, perms[i]);
            if(permValue == -1)perror("acl_get_perm");
            printf("%c", permValue ? permsSymbols[i] : '-');
        }
        printf("\n");
        printf("-------------\n");
        entryId = ACL_NEXT_ENTRY;
    }
    return 0;
}