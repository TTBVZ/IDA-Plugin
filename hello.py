import idaapi
import idc
import idautils

def main():
    print("Basic Block Plugin Starting")

    # Loop iterates through all functions within the idb (FOR BASIC BLOCK LABELING)
    for funcea in idautils.Functions():
        # Current address pointer
        currAdr = funcea
        # Address of the function's end
        funcEnd = find_func_end(funcea)

        #print(str(functionName))
        basicBlockCount = 1;
        # This function loops through every instruction in the function and labels its respective basic block
        while currAdr < funcEnd:
            # Flag to check if the basicBlockCount needs to be incremented. This is to prevent hitting
            # - two cases at once and incrementing twice
            inc_flag = False;
            # Comments the instruction with its basic block number
            idc.set_cmt(currAdr, str(basicBlockCount), 0)
            # Checks to see whether the instruction will either jump to another instruction or
            # - have other instructions jumping to it
            # This is just a check to see if the basic block follows the one entry and one exit point rule
            if len(list(idautils.CodeRefsFrom(currAdr, 0))) > 0 and idc.GetMnem(currAdr) != 'call':
                basicBlockCount += 1;
                inc_flag = True;
            currAdr = idc.next_head(currAdr, funcEnd)
            if len(list(idautils.CodeRefsTo(currAdr, 0))) and not inc_flag:
                basicBlockCount += 1;
    # Loop iterates through all functions within the idb (FOR CONTROL FLOW LABELING)
    for funcea in idautils.Functions():
        # Same as above following similar structure just different comments to change
        currAdr = funcea
        funcEnd = find_func_end(funcea)
        # The reason we check if the next instruction is past the function end is because my function looks
        # - forward to do calculations. Meaning if we are currently on the last instruction before the
        # - end then there is no point changing anything because nothing is after it
        while currAdr < funcEnd and idc.next_head(currAdr, funcEnd) < funcEnd:
            currString = idc.GetCommentEx(currAdr, 0)
            # Checks to see if the next instruction is part of another block
            nextAdr = idc.next_head(currAdr, funcEnd)
            nextString = idc.GetCommentEx(nextAdr, 0)
            if currString != nextString:
                # This checkFlag is used to differentiate between the first string concatenation and all the
                # - ones after it. The reason the first string concatenation is different is because we add
                # - the " Flows to: " string. Other iterations will just append the block number
                checkflag = True
                # If the instruction is jmp then the block will not flow into the next block because its absolute
                if nextString != None and idc.GetMnem(currAdr) != 'jmp':
                    string = currString + " Flows to: " + nextString
                    checkflag = False
                nextBlock =[]
                # Check if the instruction is call. If it is there will be a reference to another instruction
                # - but since it doesn't break the basic block we just ignore it and flow into the next block
                # - after
                if idc.GetMnem(currAdr) != 'call':
                    refs = idautils.CodeRefsFrom(currAdr,0)
                if refs:
                    # Iterate through all the references from the current instruction
                    for ref in refs:
                        # We save all the possible block numbers the current instruction can flow into
                        nextBlock.append(idc.GetCommentEx(ref, 0))
                    # We iterate through the saved blocks and concatenate them into the string
                    for block in nextBlock:
                        # Occassional cases where a saved comment holds nothing and is None. This conditional
                        # - is used to make sure that the comment is valid
                        if block != None:
                            if checkflag:
                                string = currString + " Flows to: " 
                                string = string + block
                            else:
                                string = string + ", " + block
                    idc.set_cmt(currAdr, string, 0)
            # Increment to the next instruction
            currAdr = idc.next_head(currAdr, funcEnd)
    print "Plugin Finished"

if __name__ == "__main__":
    main()

