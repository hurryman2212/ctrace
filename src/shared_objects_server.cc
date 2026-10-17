#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/SHA256.h>

#include <asm-generic/socket.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "shared_objects_protocol.h"
#include "shared_objects_server.h"

// Bound work and queued replies independently of object size and client speed.
static constexpr size_t validation_chunk = 64 * 1024;
static constexpr size_t reply_limit = 64;
static constexpr size_t catalog_scan_chunk = 256;
// Eligibility advertisements can be reconstructed from a validated live
// emission. Their eviction never releases a mapped backing object's reference.
static constexpr size_t dr_alias_limit = 4096;

struct ct_shared_broker::State {
  struct KeyLess {
    bool operator()(const ct_shared_key &left,
                    const ct_shared_key &right) const {
      return std::memcmp(&left, &right, sizeof(left)) < 0;
    }
  };
  struct Reply {
    ct_shared_packet packet{};
    int fd = -1;
    ~Reply() {
      if (fd >= 0)
        ::close(fd);
    }
  };
  struct Client {
    int fd = -1;
    int64_t process = 0;
    uint64_t session = 0;
    uint64_t id = 0;
    uint64_t last_request = 0;
    uint64_t notified = 0;
    bool closing = false;
    std::deque<std::unique_ptr<Reply>> replies;
    std::map<uint64_t, ct_shared_key> tickets;
    ~Client() {
      if (fd >= 0)
        ::close(fd);
    }
  };
  struct Session {
    int pidfd = -1;
    int64_t process = 0;
    uint64_t channels = 0;
    std::map<uint64_t, uint64_t> references;
    ~Session() {
      if (pidfd >= 0)
        ::close(pidfd);
    }
  };
  struct Object {
    ct_shared_key key{};
    uint64_t id = 0;
    uint64_t producer = 0;
    uint64_t producer_ticket = 0;
    uint64_t lease = 0;
    uint64_t references = 0;
    uint64_t publication = 0;
    std::vector<std::pair<uint64_t, uint64_t>> waiters;
    int fd = -1;
    bool validating = false;
    bool ready = false;
    uint64_t publish_request = 0;
    uint64_t hashed = 0;
    uint64_t padding_checked = sizeof(ct_shared_envelope);
    ct_shared_envelope envelope{};
    llvm::SHA256 hash;
    std::vector<std::array<unsigned char, 32>> dr_bodies;
    ~Object() {
      if (fd >= 0)
        ::close(fd);
    }
  };

  struct DRPlacement {
    uint64_t object = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
  };
  struct DRAlias {
    std::array<unsigned char, 32> body{};
    uint64_t id = 0;
  };

  struct ForkReservation {
    int fd = -1;
    uint64_t parent_session = 0;
    int64_t parent_process = 0;
    std::map<uint64_t, uint64_t> references;
    ~ForkReservation() {
      if (fd >= 0)
        ::close(fd);
    }
  };

  uint64_t next_client = 0;
  uint64_t next_object = 0;
  uint64_t next_token = 0;
  uint64_t sequence = 1;
  uint64_t next_dr_alias = 0;
  std::map<uint64_t, std::unique_ptr<Client>> clients;
  std::map<uint64_t, std::unique_ptr<Session>> sessions;
  std::map<uint64_t, std::unique_ptr<ForkReservation>> forks;
  std::map<ct_shared_key, std::unique_ptr<Object>, KeyLess> objects;
  std::map<uint64_t, ct_shared_key> identities;
  std::map<std::array<unsigned char, 32>, std::vector<DRPlacement>> dr_bodies;
  std::map<ct_shared_key, DRAlias, KeyLess> dr_aliases;
  std::map<uint64_t, ct_shared_key> dr_alias_order;

  bool reply(Client &client, const ct_shared_packet &packet, int fd = -1) {
    if (client.closing || client.replies.size() >= reply_limit) {
      client.closing = true;
      return false;
    }
    auto result = std::make_unique<Reply>();
    result->packet = packet;
    if (fd >= 0) {
      result->fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
      if (result->fd < 0) {
        client.closing = true;
        return false;
      }
    }
    client.replies.push_back(std::move(result));
    return true;
  }

  ct_shared_descriptor describe(const Object &object) const {
    ct_shared_descriptor descriptor{};
    descriptor.key = object.key;
    descriptor.object_id = object.id;
    descriptor.sequence = object.publication;
    descriptor.payload_offset = object.envelope.payload_offset;
    descriptor.payload_size = object.envelope.payload_size;
    std::memcpy(descriptor.digest, object.envelope.digest,
                sizeof(descriptor.digest));
    return descriptor;
  }

  bool grant(Client &client, Object &object, ct_shared_packet response) {
    response.status = CT_SHARED_READY;
    response.error = 0;
    response.sequence = sequence;
    response.object = describe(object);
    if (!reply(client, response, object.fd))
      return false;
    ++sessions.at(client.session)->references[object.id];
    ++object.references;
    return true;
  }

  void evict(const ct_shared_key &key) {
    const auto found = objects.find(key);
    if (found == objects.end() || !found->second->ready ||
        found->second->references || !found->second->waiters.empty())
      return;
    const uint64_t id = found->second->id;
    for (const auto &body : found->second->dr_bodies) {
      auto indexed = dr_bodies.find(body);
      if (indexed == dr_bodies.end())
        continue;
      auto &placements = indexed->second;
      placements.erase(std::remove_if(placements.begin(), placements.end(),
                                      [id](const DRPlacement &slot) {
                                        return slot.object == id;
                                      }),
                       placements.end());
      if (!placements.empty())
        continue;
      for (auto alias = dr_aliases.begin(); alias != dr_aliases.end();) {
        if (alias->second.body == body) {
          dr_alias_order.erase(alias->second.id);
          alias = dr_aliases.erase(alias);
        } else
          ++alias;
      }
      dr_bodies.erase(indexed);
    }
    identities.erase(id);
    objects.erase(found);
    ++sequence;
  }

  void fail(Object &object) {
    if (object.fd >= 0)
      ::close(object.fd);
    object.fd = -1;
    object.validating = false;
    object.publish_request = 0;
    object.hashed = 0;
    object.hash = llvm::SHA256();
    object.producer = 0;
    object.producer_ticket = 0;
    object.lease = 0;
    while (!object.waiters.empty()) {
      const auto waiter = object.waiters.front();
      const auto client = clients.find(waiter.first);
      if (client == clients.end() || client->second->closing) {
        object.waiters.erase(object.waiters.begin());
        continue;
      }
      if (next_token == UINT64_MAX) {
        client->second->closing = true;
        object.waiters.erase(object.waiters.begin());
        continue;
      }
      object.producer = waiter.first;
      object.producer_ticket = waiter.second;
      object.lease = ++next_token;
      // Keep its ticket until WAIT_STATUS observes the replacement lease.
      break;
    }
    ++sequence;
    if (!object.producer) {
      const auto key = object.key;
      identities.erase(object.id);
      objects.erase(key);
    }
  }

  void remove_client(uint64_t id) {
    auto found = clients.find(id);
    if (found == clients.end())
      return;
    auto client = std::move(found->second);
    clients.erase(found);
    auto &session = *sessions.at(client->session);
    --session.channels;
    if (!session.channels && session.references.empty())
      sessions.erase(client->session);
    for (const auto &ticket : client->tickets) {
      const auto found_object = objects.find(ticket.second);
      if (found_object == objects.end())
        continue;
      auto &waiters = found_object->second->waiters;
      waiters.erase(
          std::remove_if(waiters.begin(), waiters.end(),
                         [id](const auto &item) { return item.first == id; }),
          waiters.end());
      evict(ticket.second);
    }
    for (auto item = objects.begin(); item != objects.end();) {
      Object &object = *item->second;
      ++item;
      if (object.producer == id)
        fail(object);
    }
  }

  void remove_session(uint64_t id) {
    std::vector<uint64_t> participants;
    for (const auto &item : clients)
      if (item.second->session == id)
        participants.push_back(item.first);
    for (uint64_t participant : participants)
      remove_client(participant);
    const auto found = sessions.find(id);
    if (found == sessions.end())
      return;
    for (const auto &reference : found->second->references) {
      const auto identity = identities.find(reference.first);
      if (identity == identities.end())
        continue;
      const auto key = identity->second;
      auto &object = *objects.at(key);
      object.references -= reference.second;
      evict(key);
    }
    sessions.erase(found);
  }

  void cancel_fork(uint64_t token) {
    const auto reservation = forks.find(token);
    if (reservation == forks.end())
      return;
    for (const auto &reference : reservation->second->references) {
      const auto key = identities.at(reference.first);
      objects.at(key)->references -= reference.second;
      evict(key);
    }
    forks.erase(reservation);
  }

  void request(Client &client, const ct_shared_packet &request, int received) {
    ct_shared_packet response{};
    response.version = CT_SHARED_PROTOCOL;
    response.operation = request.operation;
    response.request = request.request;
    response.sequence = sequence;
    response.status = CT_SHARED_ERROR;
    response.error = EINVAL;
    if (request.version != CT_SHARED_PROTOCOL || !request.request ||
        request.request <= client.last_request ||
        (received >= 0 && request.operation != CT_SHARED_PUBLISH &&
         request.operation != CT_SHARED_FORK_CLAIM &&
         request.operation != CT_SHARED_FORK_RESERVE_SELECTED)) {
      if (received >= 0)
        ::close(received);
      client.closing = true;
      return;
    }
    client.last_request = request.request;
    if ((request.operation == CT_SHARED_FORK_RESERVE ||
         request.operation == CT_SHARED_FORK_RESERVE_SELECTED) &&
        next_token != UINT64_MAX) {
      const auto &owned = sessions.at(client.session)->references;
      std::map<uint64_t, uint64_t> references;
      bool valid = true;
      if (request.operation == CT_SHARED_FORK_RESERVE_SELECTED) {
        struct stat information{};
        const int seals = received >= 0 ? fcntl(received, F_GET_SEALS) : -1;
        const int required = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
                             F_SEAL_SEAL | F_SEAL_EXEC;
        valid = received >= 0 && seals >= 0 && (seals & required) == required &&
                request.cursor <= CT_SHARED_OBJECT_LIMIT / sizeof(uint64_t) &&
                fstat(received, &information) == 0 &&
                S_ISREG(information.st_mode) && !(information.st_mode & 0111) &&
                information.st_size ==
                    static_cast<off_t>(request.cursor * sizeof(uint64_t));
        std::array<uint64_t, validation_chunk / sizeof(uint64_t)> ids;
        for (uint64_t offset = 0; valid && offset < request.cursor;) {
          const size_t count =
              std::min<uint64_t>(ids.size(), request.cursor - offset);
          ssize_t bytes;
          do {
            bytes = pread(received, ids.data(), count * sizeof(uint64_t),
                          offset * sizeof(uint64_t));
          } while (bytes < 0 && errno == EINTR);
          valid = bytes == static_cast<ssize_t>(count * sizeof(uint64_t));
          for (size_t index = 0; valid && index < count; ++index) {
            const auto held = owned.find(ids[index]);
            valid =
                held != owned.end() && ++references[ids[index]] <= held->second;
          }
          offset += count;
        }
        if (received >= 0)
          ::close(received);
        received = -1;
      } else {
        references = owned;
      }
      if (!valid) {
        reply(client, response);
        return;
      }
      int pipe[2];
      if (pipe2(pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        response.error = errno;
      } else {
        auto reservation = std::make_unique<ForkReservation>();
        reservation->fd = pipe[0];
        reservation->parent_session = client.session;
        reservation->parent_process = client.process;
        reservation->references = std::move(references);
        for (const auto &reference : reservation->references)
          objects.at(identities.at(reference.first))->references +=
              reference.second;
        response.token = ++next_token;
        response.status = CT_SHARED_OK;
        response.error = 0;
        forks.emplace(response.token, std::move(reservation));
        reply(client, response, pipe[1]);
        ::close(pipe[1]);
        return;
      }
    } else if (request.operation == CT_SHARED_FORK_CLAIM && received >= 0) {
      const auto reservation = forks.find(request.token);
      struct stat expected{}, actual{};
      const int flags = fcntl(received, F_GETFL);
      const bool valid =
          reservation != forks.end() &&
          reservation->second->parent_session != client.session &&
          reservation->second->parent_process != client.process && flags >= 0 &&
          (flags & O_ACCMODE) == O_WRONLY && fstat(received, &actual) == 0 &&
          S_ISFIFO(actual.st_mode) &&
          fstat(reservation->second->fd, &expected) == 0 &&
          expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino;
      ::close(received);
      if (valid) {
        auto &references = sessions.at(client.session)->references;
        for (const auto &reference : reservation->second->references)
          references[reference.first] += reference.second;
        forks.erase(reservation);
        response.status = CT_SHARED_OK;
        response.error = 0;
      } else
        response.error = ESTALE;
    } else if ((request.operation == CT_SHARED_DR_MEMBER_ACQUIRE ||
                request.operation == CT_SHARED_DR_MEMBER_BIND ||
                request.operation == CT_SHARED_DR_MEMBER_BIND_AVAILABLE) &&
               ct_shared_key_valid(&request.key) &&
               request.key.kind == CT_SHARED_DR_CODE &&
               request.key.schema == CT_SHARED_DR_COMPACT_MEMBER_SCHEMA) {
      std::array<unsigned char, 32> body{};
      auto alias = dr_aliases.find(request.key);
      bool valid = request.operation != CT_SHARED_DR_MEMBER_BIND_AVAILABLE ||
                   request.object.object_id != 0;
      if (request.operation == CT_SHARED_DR_MEMBER_BIND ||
          request.operation == CT_SHARED_DR_MEMBER_BIND_AVAILABLE) {
        ct_shared_key expected{};
        valid = valid &&
                ct_shared_dr_compact_member_key(
                    request.key.level, request.object.key.identity,
                    request.object.digest, &expected) &&
                !std::memcmp(&expected, &request.key, sizeof(expected));
        std::memcpy(body.data(), request.object.digest, body.size());
        valid &= alias == dr_aliases.end() || alias->second.body == body;
      } else if (alias != dr_aliases.end())
        body = alias->second.body;
      auto backing = dr_bodies.find(body);
      const DRPlacement *selected = nullptr;
      if (backing != dr_bodies.end()) {
        for (const auto &slot : backing->second) {
          const auto &candidate = *objects.at(identities.at(slot.object));
          if (candidate.key.schema == CT_SHARED_DR_COMPACT_SCHEMA &&
              (!request.object.object_id ||
               slot.object == request.object.object_id)) {
            selected = &slot;
            break;
          }
        }
      }
      if (request.object.object_id &&
          request.operation != CT_SHARED_DR_MEMBER_BIND_AVAILABLE &&
          !sessions.at(client.session)
               ->references.count(request.object.object_id))
        selected = nullptr;
      if (!valid) {
        response.error = EBADMSG;
      } else if (!selected ||
                 (alias == dr_aliases.end() &&
                  request.operation == CT_SHARED_DR_MEMBER_ACQUIRE)) {
        response.status = CT_SHARED_ABSENT;
        response.error = 0;
      } else {
        if (alias == dr_aliases.end()) {
          if (next_dr_alias == UINT64_MAX) {
            response.error = EOVERFLOW;
            reply(client, response);
            return;
          }
          if (dr_aliases.size() >= dr_alias_limit) {
            dr_aliases.erase(dr_alias_order.begin()->second);
            dr_alias_order.erase(dr_alias_order.begin());
          }
          const uint64_t id = ++next_dr_alias;
          dr_aliases.emplace(request.key, DRAlias{body, id});
          dr_alias_order.emplace(id, request.key);
          ++sequence;
        }
        const DRPlacement &slot = *selected;
        Object &object = *objects.at(identities.at(slot.object));
        response.cursor = slot.offset;
        response.count = slot.size;
        grant(client, object, response);
        return;
      }
    } else if (request.operation == CT_SHARED_ACQUIRE &&
               ct_shared_key_valid(&request.key)) {
      auto found = objects.find(request.key);
      if (found == objects.end()) {
        if (next_object == UINT64_MAX || next_token == UINT64_MAX) {
          response.error = EOVERFLOW;
          reply(client, response);
          return;
        }
        auto object = std::make_unique<Object>();
        object->key = request.key;
        object->id = ++next_object;
        object->producer = client.id;
        object->lease = ++next_token;
        identities.emplace(object->id, object->key);
        found = objects.emplace(request.key, std::move(object)).first;
      }
      Object &object = *found->second;
      if (object.ready) {
        grant(client, object, response);
        return;
      }
      response.error = 0;
      response.object.key = object.key;
      if (object.producer == client.id) {
        response.status =
            object.producer_ticket ? CT_SHARED_WAIT : CT_SHARED_CREATE;
        response.token =
            object.producer_ticket ? object.producer_ticket : object.lease;
      } else if (next_token != UINT64_MAX) {
        response.status = CT_SHARED_WAIT;
        response.token = ++next_token;
        client.tickets.emplace(response.token, object.key);
        object.waiters.emplace_back(client.id, response.token);
      } else {
        response.status = CT_SHARED_ERROR;
        response.error = EOVERFLOW;
      }
    } else if (request.operation == CT_SHARED_PUBLISH && received >= 0) {
      Object *object = nullptr;
      for (auto &item : objects)
        if (item.second->producer == client.id &&
            item.second->lease == request.token) {
          object = item.second.get();
          break;
        }
      struct stat information{};
      ct_shared_envelope envelope{};
      const int seals = fcntl(received, F_GET_SEALS);
      const int required = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW |
                           F_SEAL_WRITE | F_SEAL_EXEC;
      const long page_size = sysconf(_SC_PAGESIZE);
      const bool valid =
          object && !object->producer_ticket && !object->validating &&
          !object->ready && seals >= 0 && (seals & required) == required &&
          fstat(received, &information) == 0 && S_ISREG(information.st_mode) &&
          information.st_size >= 0 &&
          pread(received, &envelope, sizeof(envelope), 0) == sizeof(envelope) &&
          ct_shared_envelope_valid(&envelope, information.st_size) &&
          ((information.st_mode & 0111) != 0) ==
              (envelope.key.kind != CT_SHARED_DECOMPILE) &&
          page_size > 0 && envelope.payload_offset % uint64_t(page_size) == 0 &&
          !std::memcmp(&envelope.key, &object->key, sizeof(object->key));
      if (valid) {
        object->fd = received;
        object->envelope = envelope;
        object->validating = true;
        object->publish_request = request.request;
        object->hashed = 0;
        object->padding_checked = envelope.header_size;
        object->hash = llvm::SHA256();
        return; // Incremental validation replies later; never block the
                // reactor.
      }
      ::close(received);
      response.error = object ? EINVAL : ESTALE;
    } else if (request.operation == CT_SHARED_FAIL) {
      Object *object = nullptr;
      for (auto &item : objects)
        if (item.second->producer == client.id &&
            item.second->lease == request.token) {
          object = item.second.get();
          break;
        }
      if (object) {
        fail(*object);
        response.status = CT_SHARED_OK;
        response.error = 0;
      } else
        response.error = ESTALE;
    } else if (request.operation == CT_SHARED_WAIT_STATUS ||
               request.operation == CT_SHARED_CANCEL_WAIT) {
      const auto ticket = client.tickets.find(request.token);
      if (ticket == client.tickets.end()) {
        response.status = CT_SHARED_ABSENT;
        response.error = 0;
      } else {
        const auto key = ticket->second;
        const auto found = objects.find(key);
        if (found == objects.end()) {
          client.tickets.erase(ticket);
          response.status = CT_SHARED_ABSENT;
          response.error = 0;
        } else {
          Object &object = *found->second;
          const bool cancel = request.operation == CT_SHARED_CANCEL_WAIT;
          const bool promoted = object.producer == client.id &&
                                object.producer_ticket == request.token;
          response.error = 0;
          response.object.key = key;
          if (cancel || object.ready || promoted) {
            auto &waiters = object.waiters;
            waiters.erase(std::remove(waiters.begin(), waiters.end(),
                                      std::make_pair(client.id, request.token)),
                          waiters.end());
            client.tickets.erase(ticket);
            if (cancel) {
              response.status = CT_SHARED_OK;
              if (promoted)
                fail(object);
              else
                evict(key);
            } else if (object.ready) {
              grant(client, object, response);
              return;
            } else {
              object.producer_ticket = 0;
              response.status = CT_SHARED_CREATE;
              response.token = object.lease;
            }
          } else {
            response.status = CT_SHARED_WAIT;
            response.token = request.token;
          }
        }
      }
    } else if (request.operation == CT_SHARED_RELEASE) {
      auto &references = sessions.at(client.session)->references;
      const auto reference = references.find(request.token);
      if (reference != references.end()) {
        const auto key = identities.at(request.token);
        auto &object = *objects.at(key);
        --object.references;
        if (!--reference->second)
          references.erase(reference);
        evict(key);
        response.status = CT_SHARED_OK;
        response.error = 0;
      } else
        response.error = ESTALE;
    } else if (request.operation == CT_SHARED_DR_MEMBER_SCAN) {
      const uint64_t upper_bound =
          request.token ? request.token : next_dr_alias;
      if (request.cursor > request.token || upper_bound > next_dr_alias) {
        response.error = EINVAL;
      } else {
        response.status = CT_SHARED_OK;
        response.error = 0;
        response.token = upper_bound;
        response.cursor = request.cursor;
        size_t examined = 0;
        auto item = dr_alias_order.upper_bound(request.cursor);
        while (item != dr_alias_order.end() && item->first <= upper_bound &&
               examined < catalog_scan_chunk &&
               response.count < CT_SHARED_SNAPSHOT_CAPACITY) {
          response.cursor = item->first;
          const DRAlias &alias = dr_aliases.at(item->second);
          const auto backing = dr_bodies.find(alias.body);
          if (backing != dr_bodies.end() && !backing->second.empty()) {
            const DRPlacement &slot = backing->second.front();
            const Object &object = *objects.at(identities.at(slot.object));
            auto &descriptor = response.entries[response.count++];
            descriptor = describe(object);
            descriptor.key = item->second;
            descriptor.payload_offset += slot.offset;
            descriptor.payload_size = slot.size;
            std::memcpy(descriptor.digest, alias.body.data(),
                        alias.body.size());
          }
          ++item;
          ++examined;
        }
        response.more =
            item != dr_alias_order.end() && item->first <= upper_bound;
        if (!response.more)
          response.cursor = upper_bound;
      }
    } else if (request.operation == CT_SHARED_SCAN) {
      const uint64_t upper_bound = request.token ? request.token : next_object;
      if (request.key.kind > CT_SHARED_DECOMPILE ||
          request.cursor > request.token || upper_bound > next_object) {
        response.error = EINVAL;
      } else {
        response.status = CT_SHARED_OK;
        response.error = 0;
        response.token = upper_bound;
        response.cursor = request.cursor;
        size_t examined = 0;
        auto item = identities.upper_bound(request.cursor);
        while (item != identities.end() && item->first <= upper_bound &&
               examined < catalog_scan_chunk &&
               response.count < CT_SHARED_SNAPSHOT_CAPACITY) {
          const Object &object = *objects.at(item->second);
          response.cursor = item->first;
          if (object.ready &&
              (!request.key.kind || object.key.kind == request.key.kind))
            response.entries[response.count++] = describe(object);
          ++item;
          ++examined;
        }
        response.more = item != identities.end() && item->first <= upper_bound;
        if (!response.more)
          response.cursor = upper_bound;
      }
    } else if (request.operation == CT_SHARED_LIST) {
      response.error = 0;
      if (request.sequence && request.sequence != sequence) {
        response.status = CT_SHARED_RESYNC;
      } else {
        response.status = CT_SHARED_OK;
        response.cursor = request.cursor;
        for (auto item = identities.upper_bound(request.cursor);
             item != identities.end(); ++item) {
          const Object &object = *objects.at(item->second);
          if (!object.ready)
            continue;
          if (response.count == CT_SHARED_SNAPSHOT_CAPACITY) {
            response.more = 1;
            break;
          }
          response.entries[response.count++] = describe(object);
          response.cursor = item->first;
        }
      }
    }
    if (request.operation == CT_SHARED_FORK_RESERVE_SELECTED && received >= 0)
      ::close(received);
    response.sequence = sequence;
    reply(client, response);
  }

  void receive(Client &client) {
    ct_shared_packet packet{};
    struct iovec vector{&packet, sizeof(packet)};
    union {
      struct cmsghdr alignment;
      char
          bytes[CMSG_SPACE(sizeof(int) * 4) + CMSG_SPACE(sizeof(struct ucred))];
    } ancillary{};
    struct msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    const ssize_t size =
        recvmsg(client.fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (size < 0 && (errno == EINTR || errno == EAGAIN))
      return;
    bool valid = size == sizeof(packet) &&
                 !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    int received = -1;
    bool authenticated = false;
    for (auto *header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
      if (header->cmsg_level == SOL_SOCKET &&
          header->cmsg_type == SCM_CREDENTIALS &&
          header->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
        struct ucred credential{};
        std::memcpy(&credential, CMSG_DATA(header), sizeof(credential));
        authenticated = credential.pid == client.process;
      } else if (header->cmsg_level == SOL_SOCKET &&
                 header->cmsg_type == SCM_RIGHTS &&
                 header->cmsg_len >= CMSG_LEN(0)) {
        const size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t index = 0; index < count; ++index) {
          int fd;
          std::memcpy(&fd, CMSG_DATA(header) + index * sizeof(fd), sizeof(fd));
          if (received < 0)
            received = fd;
          else {
            ::close(fd);
            valid = false;
          }
        }
      } else
        valid = false;
    }
    if (!valid || !authenticated) {
      if (received >= 0)
        ::close(received);
      client.closing = true;
      return;
    }
    request(client, packet, received);
  }

  void send(Client &client) {
    ct_shared_packet notification{};
    notification.version = CT_SHARED_PROTOCOL;
    notification.operation = CT_SHARED_NOTIFY;
    notification.sequence = sequence;
    const Reply *reply =
        client.replies.empty() ? nullptr : client.replies.front().get();
    const ct_shared_packet &packet = reply ? reply->packet : notification;
    struct iovec vector{const_cast<ct_shared_packet *>(&packet),
                        sizeof(packet)};
    union {
      struct cmsghdr alignment;
      char bytes[CMSG_SPACE(sizeof(int))];
    } ancillary{};
    struct msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (reply && reply->fd >= 0) {
      message.msg_control = ancillary.bytes;
      message.msg_controllen = sizeof(ancillary.bytes);
      auto *header = CMSG_FIRSTHDR(&message);
      header->cmsg_level = SOL_SOCKET;
      header->cmsg_type = SCM_RIGHTS;
      header->cmsg_len = CMSG_LEN(sizeof(int));
      std::memcpy(CMSG_DATA(header), &reply->fd, sizeof(int));
    }
    const ssize_t count =
        sendmsg(client.fd, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (count < 0 && (errno == EINTR || errno == EAGAIN))
      return;
    if (count != sizeof(packet)) {
      client.closing = true;
      return;
    }
    if (reply)
      client.replies.pop_front();
    else
      client.notified = sequence;
  }

  bool index_dr_batch(Object &object) {
    if (object.key.kind != CT_SHARED_DR_CODE ||
        object.key.schema != CT_SHARED_DR_COMPACT_SCHEMA)
      return object.envelope.header_size == sizeof(ct_shared_envelope);
    const size_t index_size =
        object.envelope.header_size - sizeof(ct_shared_envelope);
    if (object.key.level || index_size < sizeof(ct_shared_dr_compact_header) ||
        index_size > CT_SHARED_DR_COMPACT_LIMIT ||
        object.envelope.payload_size > CT_SHARED_DR_COMPACT_LIMIT ||
        std::memcmp(object.key.identity, object.envelope.digest, 32))
      return false;
    std::vector<unsigned char> index(index_size);
    if (pread(object.fd, index.data(), index.size(),
              sizeof(ct_shared_envelope)) != ssize_t(index.size()))
      return false;
    void *mapping = mmap(nullptr, object.envelope.payload_size, PROT_READ,
                         MAP_SHARED, object.fd, object.envelope.payload_offset);
    if (mapping == MAP_FAILED)
      return false;
    const bool valid = ct_shared_dr_compact_validate(
        index.data(), index.size(), mapping, object.envelope.payload_size);
    munmap(mapping, object.envelope.payload_size);
    if (!valid)
      return false;
    const auto *header =
        reinterpret_cast<const ct_shared_dr_compact_header *>(index.data());
    const auto *members = reinterpret_cast<const ct_shared_dr_compact_member *>(
        index.data() + sizeof(*header));
    for (uint32_t i = 0; i < header->count; ++i) {
      std::array<unsigned char, 32> body;
      std::memcpy(body.data(), members[i].identity, body.size());
      dr_bodies[body].push_back(
          DRPlacement{object.id, members[i].offset, members[i].size});
      object.dr_bodies.push_back(body);
    }
    std::sort(object.dr_bodies.begin(), object.dr_bodies.end());
    object.dr_bodies.erase(
        std::unique(object.dr_bodies.begin(), object.dr_bodies.end()),
        object.dr_bodies.end());
    return true;
  }

  void validate() {
    for (auto &entry : objects) {
      Object &object = *entry.second;
      if (!object.validating)
        continue;
      const auto producer = clients.find(object.producer);
      if (producer == clients.end() || producer->second->closing) {
        fail(object);
        return;
      }
      std::array<unsigned char, validation_chunk> bytes;
      const bool padding =
          object.padding_checked < object.envelope.payload_offset;
      const uint64_t index_size =
          object.envelope.header_size - sizeof(ct_shared_envelope);
      const bool index = object.hashed < index_size;
      const size_t size = std::min<uint64_t>(
          bytes.size(),
          padding ? object.envelope.payload_offset - object.padding_checked
          : index ? index_size - object.hashed
                  : index_size + object.envelope.payload_size - object.hashed);
      const ssize_t count =
          size ? pread(object.fd, bytes.data(), size,
                       padding ? object.padding_checked
                       : index ? sizeof(ct_shared_envelope) + object.hashed
                               : object.envelope.payload_offset +
                                     object.hashed - index_size)
               : 0;
      if (count < 0 && errno == EINTR)
        return;
      bool valid = count == ssize_t(size);
      if (valid && padding) {
        valid = std::all_of(bytes.begin(), bytes.begin() + size,
                            [](unsigned char value) { return value == 0; });
        if (valid) {
          object.padding_checked += size;
          return;
        }
      }
      if (valid && size) {
        object.hash.update(llvm::ArrayRef<uint8_t>(bytes.data(), size));
        object.hashed += size;
      }
      if (valid && object.hashed != index_size + object.envelope.payload_size)
        return;
      const auto digest = object.hash.final();
      valid &=
          !std::memcmp(digest.data(), object.envelope.digest, digest.size());
      if (valid)
        valid = index_dr_batch(object);
      ct_shared_packet response{};
      response.version = CT_SHARED_PROTOCOL;
      response.operation = CT_SHARED_PUBLISH;
      response.request = object.publish_request;
      if (!valid) {
        response.status = CT_SHARED_ERROR;
        response.error = EBADMSG;
        response.sequence = sequence;
        reply(*producer->second, response);
        fail(object);
        return;
      }
      object.validating = false;
      object.ready = true;
      object.publication = ++sequence;
      object.producer = 0;
      object.lease = 0;
      if (!grant(*producer->second, object, response))
        evict(object.key);
      return; // At most one chunk or completion per event-loop iteration.
    }
  }
};

ct_shared_broker::ct_shared_broker() : state(std::make_unique<State>()) {}
ct_shared_broker::~ct_shared_broker() = default;

bool ct_shared_broker::connect(int fd, int64_t process, uint64_t session) {
  if (fd < 0 || process <= 0 || process > INT32_MAX || !session ||
      state->next_client == UINT64_MAX)
    return false;
  int type = 0;
  socklen_t length = sizeof(type);
  const int flags = fcntl(fd, F_GETFL);
  int credentials = 1;
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0 ||
      type != SOCK_SEQPACKET || flags < 0 ||
      fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &credentials,
                 sizeof(credentials)) != 0)
    return false;
  struct ucred peer{};
  length = sizeof(peer);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0 ||
      peer.pid != process)
    return false;
  int pidfd = -1;
  length = sizeof(pidfd);
  // Unlike pidfd_open(credential.pid), this cannot bind a reused PID if the
  // producer exits between its authenticated request and this lookup.
  if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &length) != 0 ||
      pidfd < 0)
    return false;
  if (fcntl(pidfd, F_SETFD, FD_CLOEXEC) != 0) {
    ::close(pidfd);
    return false;
  }
  pollfd alive{pidfd, POLLIN, 0};
  if (poll(&alive, 1, 0) != 0) {
    ::close(pidfd);
    return false;
  }
  auto client = std::make_unique<State::Client>();
  const auto existing = state->sessions.find(session);
  if (existing != state->sessions.end()) {
    pollfd alive{existing->second->pidfd, POLLIN, 0};
    if (existing->second->process != process || poll(&alive, 1, 0) != 0) {
      ::close(pidfd);
      return false;
    }
    ::close(pidfd);
  } else {
    auto owner = std::make_unique<State::Session>();
    owner->pidfd = pidfd;
    owner->process = process;
    state->sessions.emplace(session, std::move(owner));
  }
  ++state->sessions.at(session)->channels;
  client->fd = fd;
  client->process = process;
  client->session = session;
  client->id = ++state->next_client;
  client->notified = state->sequence;
  ct_shared_packet response{};
  response.version = CT_SHARED_PROTOCOL;
  response.operation = CT_SHARED_HELLO;
  response.status = CT_SHARED_OK;
  response.token = client->id;
  response.sequence = state->sequence;
  state->reply(*client, response);
  state->clients.emplace(client->id, std::move(client));
  return true;
}

void ct_shared_broker::close_session(uint64_t session) {
  state->remove_session(session);
}

void ct_shared_broker::append_poll(std::vector<pollfd> &descriptors) const {
  for (const auto &item : state->clients) {
    const auto &client = *item.second;
    const short events =
        POLLIN |
        ((!client.replies.empty() || client.notified != state->sequence)
             ? POLLOUT
             : 0);
    descriptors.push_back({client.fd, events, 0});
  }
  for (const auto &session : state->sessions)
    descriptors.push_back({session.second->pidfd, POLLIN, 0});
  for (const auto &reservation : state->forks)
    descriptors.push_back({reservation.second->fd, POLLIN, 0});
}

void ct_shared_broker::service(const std::vector<pollfd> &descriptors) {
  for (const auto &descriptor : descriptors) {
    if (!descriptor.revents)
      continue;
    for (auto entry = state->sessions.begin();
         entry != state->sessions.end();) {
      const auto id = entry->first;
      const auto pidfd = entry->second->pidfd;
      ++entry;
      if (descriptor.fd == pidfd)
        state->remove_session(id);
    }
    for (auto entry = state->forks.begin(); entry != state->forks.end();) {
      const auto token = entry->first;
      const auto fd = entry->second->fd;
      ++entry;
      if (descriptor.fd == fd)
        state->cancel_fork(token);
    }
  }
  // Process deaths before requests can reuse an old poll snapshot's fd numbers.
  for (const auto &descriptor : descriptors) {
    if (!descriptor.revents)
      continue;
    for (auto &entry : state->clients) {
      auto &client = *entry.second;
      if (descriptor.fd != client.fd || client.closing)
        continue;
      if (descriptor.revents & (POLLHUP | POLLERR | POLLNVAL))
        client.closing = true;
      else {
        if (descriptor.revents & POLLIN)
          state->receive(client);
        if ((descriptor.revents & POLLOUT) && !client.closing)
          state->send(client);
      }
    }
  }
  for (auto item = state->clients.begin(); item != state->clients.end();) {
    auto &client = *item->second;
    ++item;
    if (client.closing)
      state->remove_client(client.id);
  }
  state->validate();
}

bool ct_shared_broker::validating() const {
  return std::any_of(
      state->objects.begin(), state->objects.end(),
      [](const auto &entry) { return entry.second->validating; });
}

void ct_shared_broker::close_for_worker() {
  // Analysis workers must not keep siblings' producer connections or object
  // descriptors alive after the broker forks them.
  state = std::make_unique<State>();
}
