from scanner.nuclei import run_nuclei


def main():
    target = "http://localhost:4280"

    output = run_nuclei(target)

    print(f"\nResults saved to: {output}")


if __name__ == "__main__":
    main()
    