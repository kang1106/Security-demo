#ifndef LOG_HPP_
#define LOG_HPP_

#include <string>

class seclog {
  public:
    void info(const std::string str);
    void info(const std::string str, const int i);
    void debug(const std::string str);
    void warning(const std::string str);
};

#endif /* LOG_HPP_ */