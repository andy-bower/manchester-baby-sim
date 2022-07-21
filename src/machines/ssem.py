
from datetime import datetime
from pathlib import Path
from time import sleep
from timeit import default_timer as timer

from src.core.bitarray import BitArray, b
from src.core.store import Store
from src.machines.abstractmachine import AbstractMachine, MachineRuntimeError
from src.machines.assembler import Assembler
from src.machines.ssemmodel import SsemModel


class Ssem(AbstractMachine):
    """Simulator for the original Small-Scale Experimental Machine (SSEM), a.k.a. Manchester Baby built in 1948

    It features:
        - A store of 32 words of 32 bits each (1024 bits total)
        - A program counter (CI) of 32 bits
        - An accumulator (A) of 32 bits
        - 7 instructions:
            - JMP S: Jump to the address specified at the address S
            - JRP S: Jump to the instruction at address CI + value of S
            - LDN S: Load the negative value of address S to the accumulator
            - STO S: Stores the value of the accumulator to address S
            - SUB S: Substract the value in address S from the accumulator
            - CMP: Skip next instruction if the accumulator contains a negative value
            - STP: Stop the execution
        - Address size: 5 bits
        - Typically performs at around 700 instructions per seconds
    """

    def __init__(self, file: Path | None = None):
        self.model = SsemModel()
        self.assembler = Assembler(model=self.model)

        self.store = Store(self.model.word_length, self.model.word_count)
        self.ci = BitArray(self.model.word_length)
        self.a = BitArray(self.model.word_length)
        self.stop_flag = True

        if file:
            self.assembler.load_file(file, self.store)

    def instruction_cycle(self) -> str:
        """Performs one instruction cycle

        It first increments the program counter, then decodes the next instruction and executes it.
        """
        # Fetch
        ci_int = self.ci.to_int()
        ci_int += 1
        ci_int %= self.model.word_count  # Program counter loops back to the begining when it exceeds the store boundaries
        self.ci = b(ci_int, self.model.word_length)

        # Decode
        word = self.store[ci_int]
        command, data = self.assembler.decode_instruction(word)

        # Execute
        try:
            self._execute(command, data)
        except IndexError:
            raise MachineRuntimeError("Error: Out of bound memory access")

        return f"{ci_int:02d} {command.name} {data:02d}"

    def _execute(self, command, data: BitArray):
        """Execute an instruction
        """
        match command:
            case self.model.Mnemonic.JMP:
                # Change the next address to execute
                self.ci = b(self.store[data])  # Copy the array

            case self.model.Mnemonic.JRP:
                # Jump to the instruction at address CI + value of S
                value = self.store[data].to_int()
                ci_int = self.ci.to_int()
                self.ci = b(value + ci_int, self.model.word_length)

            case self.model.Mnemonic.LDN:
                # Fetch the negated value
                value = -self.store[data].to_int()
                # Save it to the accumulator
                self.a = b(value, self.model.word_length)

            case self.model.Mnemonic.STO:
                # Save the value of the accumulator to the given address
                self.store[data] = b(self.a)

            case self.model.Mnemonic.SUB | self.model.Mnemonic.SUB2:
                s_int = self.store[data].to_int()
                a_int = self.a.to_int()
                # Save (accumulator - S) to the accumulator
                self.a = b(a_int - s_int, self.model.word_length)

            case self.model.Mnemonic.CMP:
                # Skip next line if accumulator is negative
                if self.a.to_int() < 0:
                    ci_int = self.ci.to_int() + 1
                    self.ci = b(ci_int, self.model.word_length)

            case self.model.Mnemonic.STP:
                self.stop_flag = True

            case _:
                raise Exception(f"Unsuported command '{command.value}'")

    def start(self):
        """Start the machine until stop instruction is met
        """

        self.stop_flag = False
        instruction = ""
        step = 0
        last_work_time = 1
        last_cycle_time = 1
        overall_start = datetime.utcnow()

        while not self.stop_flag:
            start = timer()

            instruction = self.instruction_cycle()
            step += 1

            # TODO: make a proper interface
            # print("\33[2J") # clear the screen

            print(f"[ STATUS: RUNNING ]  [ STEP: {step} ]  [ {instruction} ]  [ TIME: {datetime.utcnow() - overall_start} ]  [ SPEED: {int(round(1 / last_cycle_time, 0))} ips ]")
            print(f"{self.ci}  CI")
            print(f"{self.a}  A")
            print()
            store_str = str(self.store).split("\n")
            ci_int = self.ci.to_unsigned_int()
            store_str[ci_int] = "\033[1m" + store_str[ci_int] + "\033[0m"
            print("\n".join(store_str))

            last_work_time = timer() - start

            sleep(max(0, (1 / self.model.typical_speed) - last_work_time))
            last_cycle_time = timer() - start

    def clear_memory(self):
        """Reset the store to zero"""
        self.store.clear()

    def clear_state(self):
        """Reset the program counter and the accumulator to zero"""
        self.ci = BitArray(self.model.word_length)
        self.a = BitArray(self.model.word_length)

