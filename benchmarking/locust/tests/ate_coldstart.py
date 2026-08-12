# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Cold-start / TTFE (time-to-first-execution) benchmark user.

The warm-loop user (ate_api.AteAPIUser) creates ONE actor in on_start and then
spins GetActor -> ResumeActor -> SuspendActor forever, so it measures
steady-state per-op latency on an already-warmed actor. It cannot see the
cold-start cost: the first activation of a fresh actor from its golden
snapshot, which is the number that decides how fast a scale-from-zero burst
of new actors becomes usable.

This user measures exactly that, once per simulated user:

    CreateActor (fresh, never-resumed name)
      -> ResumeActor (the first resume-from-golden-snapshot: the cold start)
      -> GetActor    (first read confirming the actor is up / executable)

then fires a composite ``ttfe/ColdStart`` request event spanning the whole
create->first-read wall time, cleans the actor up, and StopUser()s. Because
each user provisions its own fresh actor and stops after one sample
(provision-per-sample, no warm loop), a run with N users yields N independent
cold-start samples under N-concurrent activation — the ladder rung the
SLO-knee post-processor (automation/slo_knee.py) consumes. The per-leg
CreateActor / ResumeActor / GetActor latencies are ALSO reported (via
traced_grpc) so a regression can be localized to a leg.

Additive: a new test file selected by tests.yaml; it does not touch the warm
path or its metrics.
"""

import logging
import time
import uuid

import grpc
from locust import User, task
from locust.exception import StopUser

from common import ateapi_pb2
from common import ateapi_pb2_grpc
from common.ateapi_channel import ateapi_channel
from common.atespace import ATESPACE, ensure_atespace
from common.grpc_tracing import traced_grpc
from common.metrics import init_metrics, update_user_count
from common.trace import init_tracing
from common.wait_time import init_wait_time, dynamic_wait_time

logger = logging.getLogger(__name__)

init_tracing()
init_metrics()
init_wait_time()

# The golden-snapshot actor template the cold-start resumes from — the same
# demo counter the warm user provisions, so cold vs warm ResumeActor latencies
# are directly comparable across runs.
ACTOR_TEMPLATE_NAMESPACE = "ate-demo-counter"
ACTOR_TEMPLATE_NAME = "counter"


class AteColdStartUser(User):
    wait_time = dynamic_wait_time

    host = "api.ate-system.svc.cluster.local:443"

    def on_start(self) -> None:
        update_user_count(1, self.__class__.__name__)
        self.channel = ateapi_channel(self.host)
        self.stub = ateapi_pb2_grpc.ControlStub(self.channel)
        try:
            ensure_atespace(self.stub, self.__class__.__name__)
        except Exception as e:
            # Setup, not part of the measured cold start; a concurrent user
            # will have created it (ALREADY_EXISTS is handled in ensure).
            logger.warning("Failed to ensure atespace %s: %s", ATESPACE, e)

    def on_stop(self) -> None:
        update_user_count(-1, self.__class__.__name__)
        self.channel.close()

    def _cleanup(self, actor_ref) -> None:
        """Best-effort teardown so a run doesn't leak fresh actors. Not part
        of the measured TTFE, but suspend is still traced for visibility."""
        try:
            with traced_grpc("SuspendActor", self.__class__.__name__) as md:
                _, md.call = self.stub.SuspendActor.with_call(
                    ateapi_pb2.SuspendActorRequest(actor=actor_ref),
                    metadata=md,
                )
        except Exception:
            pass
        try:
            self.stub.DeleteActor(
                ateapi_pb2.DeleteActorRequest(actor=actor_ref)
            )
        except Exception:
            pass

    @task
    def cold_start_once(self) -> None:
        cls = self.__class__.__name__
        actor_name = f"cs-{uuid.uuid4()}"
        actor_ref = ateapi_pb2.ObjectRef(atespace=ATESPACE, name=actor_name)

        # Composite TTFE spans create -> first successful read. perf_counter is
        # monotonic so a wall-clock step can't produce a negative sample.
        ttfe_start = time.perf_counter()
        ttfe_exception = None
        try:
            with traced_grpc("CreateActor", cls) as md:
                _, md.call = self.stub.CreateActor.with_call(
                    ateapi_pb2.CreateActorRequest(
                        actor=ateapi_pb2.Actor(
                            metadata=ateapi_pb2.ResourceMetadata(
                                atespace=ATESPACE, name=actor_name
                            ),
                            actor_template_namespace=ACTOR_TEMPLATE_NAMESPACE,
                            actor_template_name=ACTOR_TEMPLATE_NAME,
                        )
                    ),
                    metadata=md,
                )

            # First resume from the golden snapshot: the cold-start activation.
            with traced_grpc("ResumeActor", cls) as md:
                _, md.call = self.stub.ResumeActor.with_call(
                    ateapi_pb2.ResumeActorRequest(actor=actor_ref),
                    metadata=md,
                )

            # First read: the actor is now up and executable.
            with traced_grpc("GetActor", cls) as md:
                _, md.call = self.stub.GetActor.with_call(
                    ateapi_pb2.GetActorRequest(actor=actor_ref),
                    metadata=md,
                )
        except grpc.RpcError as e:
            ttfe_exception = e
        finally:
            ttfe_ms = (time.perf_counter() - ttfe_start) * 1000.0
            # Composite cold-start metric: type "ttfe", name "ColdStart" ->
            # JSONL metric "ttfe_ColdStart"; target it with
            #   slo_knee.py --op ColdStart --slo 5s
            self.environment.events.request.fire(
                request_type="ttfe",
                name="ColdStart",
                response_time=ttfe_ms,
                response_length=0,
                exception=ttfe_exception,
            )

        self._cleanup(actor_ref)
        # Exactly one cold-start sample per user (provision-per-sample); stop
        # so the next sample is a genuinely fresh actor, not a warm re-hit.
        raise StopUser()
