//
//  utils.hpp
//  Headshot
//
//  Created by Jai  Verma on 11/09/19.
//  Copyright © 2019 Jai  Verma. All rights reserved.
//

#ifndef utils_h
#define utils_h

#include <vector>
#include <fstream>

template <typename T>
int saveTensorToFile(std::vector<T> tensor, std::string outFilePath) {
    std::ofstream outFile;
    outFile.open(outFilePath, std::ios::binary | std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open " << outFilePath << " for writing\n";
        return 1;
    }
    for (auto &i : tensor) {
        outFile.write(reinterpret_cast<char*>(&i), sizeof(T));
    }
    outFile.close();
    return 0;
}

#endif /* utils_h */
