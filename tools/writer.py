class Writer:
    def __init__(self, path: str) -> None:
        self.f = open(path, "w")

    def close(self) -> None:
        self.f.close()

    def write_direct(self, value: str) -> None:
        self.f.write(value)

    def write(
        self,
        prefix: str, name: str, bracket: tuple[str, str], value: list[int], suffix: str,
        r: int = 16, p: int = 2
    ) -> None:
        # prefix name = bracket[0]
        #   v_1, ..., v_r,
        #   .
        #   .
        #   .
        #   v_{rk + 1}, ..., v_{r(k+1)}
        # bracket[1]suffix
        #

        self.f.write(f"{prefix}{name} = {bracket[0]}\n")
        for i in range(len(value)):
            if i % r == 0:
                self.f.write("    ")

            # write each v_i as hex (padded to multiple of 2) in uppercase with prefix 0x
            v = hex(value[i])[2:].upper()
            if len(v) % 2 != 0:
                v = "0" + v
            # extra padding
            if len(v) < p:
                v = "0" * (p - len(v)) + v
            v_i = "0x" + v
            self.f.write(v_i)
            # seperate each entry with comma and space, seperate last one with newline
            if i == len(value) - 1:
                self.f.write("\n")
            elif i % r == (r - 1):
                self.f.write(",\n")
            else:
                self.f.write(", ")
        # if len(value) is a multiple of r, there is already a newline present
        if len(value) % r == 0:
            self.f.write(f"{bracket[1]}{suffix}\n\n")
        else:
            self.f.write(f"\n{bracket[1]}{suffix}\n\n")

