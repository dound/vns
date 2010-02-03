"""The DDRQueue module implements a Queue subclass for use with Deficit Round
Robin (DRR) like algorithms."""

from Queue import Queue, Empty

class DRRQueue(Queue):
    """Implements a queue for use with a DRR-like algorithm.  Each queue tracks
    "quanta" available to it (some unit of work - for the original DRR, this was
    the number of bytes which could be sent).  start_service() is used to
    initiate a new round of service on the queue.  task_done() should be called
    each time a "job" from the queue is finished so that the appropriate quanta
    can be deducted.  When task_done() returns None, then no more quanta are
    available for jobs from this queue this round.

    Like the original, leftover quanta are only maintained if the queue is
    non-empty.  Unlike the original, jobs are run until the quanta available is
    less than or equal to zero.

    put() or put_nowait() can be used to add jobs to the queue.

    Note: This queue can be used with ordinary round robin scheme by making the
    quantum 1 and always calling task_done() with quanta_used=1.
    """
    def __init__(self, maxsize=0, quantum=1):
        """Creates a simple JobQueue.  Use put_nowait() to add jobs to the
        queue."""
        Queue.__init__(self, maxsize)
        self.deficit_counter = 0    # number of "quanta" which are available for use
        self.quantum = quantum      # how much "quanta" to add each round of service

    def start_service(self, quantum=None):
        """Allocates a new quantum to this queue and returns the next job from
        this queue if sufficient quanta are available to this queue.  The quanta
        added will be self.quantum unless quantum is specified.  The next job to
        run is returned (if any)."""
        # a new quantum of service is now available to this queue
        self.deficit_counter += (self.quantum if quantum is None else quantum)
        return self.__next_task()

    def task_done(self, quanta_used=1):
        """Informs the queue that a job has been completed.  quanta_used will be
        subtracted from the amount of quanta available for jobs on this queue.
        Returns the next job from this queue if sufficient quanta are available.
        If sufficient quanta are not available or the queue is empty, then None
        is returned."""
        Queue.task_done(self)
        self.deficit_counter -= quanta_used
        return self.__next_task()

    def __next_task(self):
        """Returns the next job from this queue if sufficient quanta are available.
        If sufficient quanta are not available or the queue is empty, then None
        is returned."""
        if self.deficit_counter > 0:
            try:
                return self.get_nowait()
            except Empty:
                # when the queue empties, any leftover quanta are lost
                self.deficit_counter = 0

        # no jobs OR insufficient quanta are left
        return None
