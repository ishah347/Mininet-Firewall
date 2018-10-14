from cs50 import get_int


def main():
    # Prompt user for height (m) until a value between 0 and 23 is given
    while True:
        m = get_int('height: ')
        if m >= 0 and m <= 23:
            break

    # Calculate pyramid's width (height + 1)
    w = m + 1
    # Iterate over pyramid's rows
    for i in range(m):
        # Iterate over pyramid's columns
        for j in range(w):
            # Print spaces so that top row of pyramid has two hashes
            if (j < w - 2 - i):
                print(' ', end='')
            # Print hashes
            else:
                print('#', end='')
        # End line and go to next line until height is reached
        print()


if __name__ == '__main__':
    main()
