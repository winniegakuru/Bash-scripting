Common Conditions

- Equality (==) Ex: `[ "$var1" == "$var2" ]`
- Inequality (!=) EX: `[ "$var1" != "$var2" ]`
- Greater than (-gt) Ex: `[ "$var1" -gt "$var2" ]`
- Greater than or equal to (-ge) Ex: `[ "$var1" -ge "$var2" ]`
- Less than (-lt) Ex: `[ "$var1" -lt "$var2" ]`
- Less than or equal to (-le) Ex: `[ "$var1" -le "$var2" ]`
- File existence (-e): This condition checks if a file or directory exists. Ex: `[ -e "$file_path" ];`
- -z (checks if a string is empty) Ex: `[ -z "$var" ]`
- -n (checks if a string is not empty) Ex: `[ -n "value" ]`
- = (checks if two strings are equal) Ex: `[ "$var" = "value" ]`
- Logical AND (&&) `[ condition1 ] && [ condition2 ]`
- Logical OR (||)  `[ condition1 ] || [ condition2 ]`
- File type (-d, -f, -L): These conditions check the type of a file or directory, such as whether it is a directory (-d), a regular file (-f), or a symbolic link (-L)
Ex: 
```
if [ -d "$dir_path" ]; then
    # Code to be executed if dir_path is a directory
elif [ -f "$file_path" ]; then
    # Code to be executed if file_path is a regular file
elif [ -L "$link_path" ]; then
    # Code to be executed if link_path is a symbolic link
else
    # Code to be executed for other cases
fi
```

- @ - In the context of a for loop in Bash, @ is used to refer to all elements in an array
```
files=("file1.txt" "file2.txt" "file3.txt")
for file in "${files[@]}"; do
    # Loop body
    echo "Processing file: $file"
done

```
