#ifndef CONTEXT_HPP_
#define CONTEXT_HPP_

#include <memory>
#include "apps/log.hpp"

class seclog;

class context {
  public:
    std::shared_ptr<seclog> log_;
};

#endif /* CONTEXT_HPP_ */