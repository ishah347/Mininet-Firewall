from cs50 import get_float


def main():
    # Prompt user for float value for change until nonnegative value is given
    while True:
        change = get_float('Change owed: ')
        if change > 0:
            break

    # Convert change (in dollars) to integer amount of cents
    cents = round(change * 100)
    # Initialize counter for coins
    coins = 0
    # Add as many 25-cent groups (quarters) as possible from cents into counter
    coins += cents // 25
    # Cents remaining is the remainder from the amount of cents before being divided by 25
    cents = cents % 25
    # Add as many 10-cent groups (dimes) as possible from cents into counter
    coins += cents // 10
    # Cents remaining is the remainder from the amount of cents before being divided by 10
    cents = cents % 10
    # Add as many 5-cent groups (nickels) as possible from cents into counter
    coins += cents // 5
    # Cents remaining is the remainder from the amount of cents before being divided by 5
    cents = cents % 5
    # Add remaining cents (pennies) to counter
    coins += cents
    # Print counter
    print(coins)


if __name__ == '__main__':
    main()
