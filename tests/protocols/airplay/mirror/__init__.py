"""Tests for pyatv's AirPlay screen-mirroring support.

WHAT VERIFIES WHAT.  The FairPlay handshake under
``pyatv/protocols/airplay/mirror/fairplay_sap/`` was recovered from
the reference sender's binary by devirtualisation.  Two things check it, and they
check different claims:

* ``fply_pure_golden.jsonl`` -- 256 recorded handshakes, committed, and
  the only check that runs on a clone.  It pins the ANSWERS: for each M2,
  the SAP secret, the device tag, the M4 context prefix and the ekey.
* ``examples/mirror_pyfply/devirt/`` -- replays Apple's own code under an
  emulator and compares the recovered ports against it, window by window.
  Its 464 MB oracle is gitignored and not redistributable, so those tests
  skip here.  See that directory's README.

MUTATION TESTING, AND WHY SOME TESTS LOOK ODD.  Line coverage of this
package reached 100% on several modules while mutations to those same
lines went unnoticed -- coverage says a line RAN, not that anything would
notice if it were wrong.  Four mutation classes were run against every
module: constants, binary operators, comparisons, and inverted ``if``
conditions.  115 of 115 mutations died in the hand-written FairPlay
modules; the transport modules left 8 survivors, each verified to be an
equivalent mutant (a slice past a fixed length, a log-truncation width,
an initialiser nothing observes).

A later campaign extended this mechanically: 186 comparison and boolean
mutations across the transport modules, 76% killed, and a separate sample of
14 in the recovered ``fairplay_sap`` crypto, all 14 killed.  That contrast is
the useful part.  The recovered handshake is pinned tightly because 256
recorded handshakes must reproduce byte-exactly, so no mutation of it can
hide; the transport survivors are all in the live-encoder and screen-audio
paths named below, logging arguments, or ``frozen=True`` on dataclasses
nothing hashes.

A third campaign redid the comparison operators once the harness itself was
trustworthy -- see the note at the end of this file for what it had been
reporting wrongly.  95 sites: `pacer` 9, the transport four 16, the handshake
and helper modules 29, ``session`` 41.  Four were real and are now pinned --
where the pacer's sleeps land, the fragment-count edge at 255, the
roll-over boundary at exactly half a sequence space, and the audio sync
cadence that a five-frame test never reaches (only the last of these is
still in the package).  A second pass shifted the
numeric threshold in each comparison instead of the operator, which is a
sharper instrument than it sounds: RAISING a guard is caught every time,
because something valid stops being accepted, while LOWERING one only
admits inputs no test sends.  Three more came out of that, all of them a
guard protecting a slice on the next line -- ``parse_header`` at 20 bytes,
``build_avcc`` at four, ``parse_m2`` at 142 (the first two have since been
removed with the code they guarded).

The rest were read one at a time rather than counted.  Most sat behind the
live video and audio commands, and the conclusion drawn here at first --
that those paths cannot be mutation-tested at all -- was too strong.  They
can, and now are; see the section below on what that took.  What genuinely
resists is narrower: two drop-oldest branches that need the reader to
outrun the sender, an 8192-byte frame cap, and a handful of equivalent
mutants where both spellings compute the same thing.

A fourth pass shifted each constant bound of every byte slice, on the
theory that a wire protocol's bugs live in its offsets.  About 110 of them,
and the yield was ZERO -- which is the useful part.  The golden handshakes
pin those offsets byte-exactly, so almost every shift dies at once, and the
survivors fall into two kinds that are worth naming because they will
recur.  An upper bound raised past the data's actual length is inherently
equivalent: ``m2[14:142]`` and ``m2[14:143]`` are the same 128 bytes when
the message is 142 long, so half that class is dead on arrival.  And a
slice inside a logging call cannot be observed at all -- ``ekey[:24].hex()``
in a debug line, ``body[:200].hex()`` in another.  The one real find was
not a slice of data but of derived key material: an HMAC output split into
a key and salt, where a short slice still looks like a key to everything
downstream (that derivation has since been removed).

A fifth pass swapped the operands of every byte concatenation, on the
grounds that ``sha512(a + b)`` for ``sha512(b + a)`` is easy to write and
impossible to see; a sixth replaced every returned expression with
``None``.  The sixth found nothing at all -- 56 sites, 56 dead -- which
says the package's return values are all looked at by something, and is
worth recording so nobody runs it again.  The fifth is where the two worst
gaps of the lot turned up, both keys: the audio key's halves could be
swapped, and the video access unit's SEI could trade places with its
slice, with every assertion in the package still passing.  Both were
caught only once a test DECRYPTED what was sent rather than measuring it,
which is the lesson under both of them -- packet counts, payload lengths
and sync cadence all hold just as well under a key the receiver does not
share.

Two of those survivors were real, and neither was a missing assertion:
``tcp_video_producer`` selected the SPS by NAL type with nothing
checking the resulting avcC, and a switch guarded a filter that could never
fire because the parameter sets had already been removed twenty lines
earlier (the switch is gone).  A third pointed at dead code rather than a test gap --
``getattr(self, name, default)`` on attributes ``__init__`` always sets.

Real defects came out of the original campaign, and the tests that
killed them are deliberately shaped around the mutant rather than around the
happy path.
Do not "simplify" these into something more obvious -- the obvious
version is what was there before, and it passed:

* ``test_tcp_stream.py``'s
  ``test_group_access_units_does_not_split_on_an_sei_nal``
  -- a TRAILING SEI is flushed by the tail either way; only an SEI
  followed by a slice distinguishes the two readings.
* ``test_tcp_stream.py``'s
  ``test_avcc_config_follows_the_decoder_configuration_record_layout``
  -- asserts the record's LAYOUT, not a captured blob; a blob regenerated
  from mutated code would launder the bug.

WHAT IS STILL UNTESTED, DELIBERATELY.  Less than this section used to
claim.  What is genuinely out of reach is whether the key derivations
produce the key a real receiver expects.

The live-encoder path (``video_command``) and the audio subprocess reader
were on that list too, on the grounds that they need an external encoder.
That was true of end-to-end fidelity and not of the parsing, which is most
of what those branches are: both take a shell command, and a few lines of
Python writing bytes to stdout is a shell command.  ``test_session_error_paths``
now drives each from a hand-built stream -- Annex-B NAL units for the video,
length-prefixed frames for the audio.  What that reaches is the NAL
classification, the access-unit grouping, and the audio's resync after a
malformed length.  Both drop-oldest branches are reached too, and neither
needed a race to do it. Each sender pauses before its first send -- the
video one sleeps ``LIVE_VIDEO_PREBUFFER``, the audio one loops on
``AUDIO_PREBUFFER`` in 50ms steps -- and that pause is the reader's
head start. Both were recorded here as out of reach before anyone tried,
and so was the 8192-byte audio frame cap, which needed nothing more than a
frame of exactly that length and a bogus prefix one byte over it.  All three
notes were guesses; none survived an attempt.  Nothing in this section is
now claimed to be untestable short of hardware.

THE SEAM HUNT, AND ITS RESULT.  A test can cover every line of session.py
and still never look at what the session *says*: the fake receiver captured
SETUP bodies that nothing opened.  The mechanical form of the question is

    fields session.py reads off MirrorContext, minus every name any test
    mentions

which started at 10 of 29 and is now 0 of 28.  Closing them turned up two
real defects rather than just missing assertions:

* an explicit ``ctx.video_encryptor`` was silently dropped in the shipping
  configuration -- the keybuf arm reassigned over the top of it, so the
  caller's encryptor encrypted zero frames with a raw16 present;
* ``audio_stream_connection_id`` was written and never read, by symmetry
  with a video field that genuinely is the single source of truth.

Rerun the scan after adding a context field.  A field that reaches the wire
wants a test that asserts the wire carries *the context's* value -- following
the context rather than pinning a literal, so a configurable identity stays
configurable.

ANNOUNCED VALUES MUST BE TIED TO WHAT THE SENDER ACTUALLY DOES.  Every
mismatch of this kind in this protocol fails silently: the receiver accepts
the packets and ignores them, or derives a different key, and the result is a
black screen on a session that looks healthy.  Nothing raises, so nothing
prompts a test to be written -- which is why three of these were unguarded
until swept for deliberately.

Each SETUP value that comes from a runtime object was mutated to disagree
with its source, and the suite run:

* ``timingPort`` -- announced vs the live ``TimingServer``.  Was unguarded;
  the fake's message claims to check boundness and only checks the range.
* ``streamConnectionID`` (video) -- announced vs the id folded into the key.
  Was unguarded in the direction that matters, and guarded in the other.
* ``controlPort`` (audio) -- announced vs the socket the sync is sent from.
* ``eiv`` (audio and video) -- announced vs the iv used to encrypt.

The last two were already caught.  One value has nothing to tie it to:
``streamConnectionID`` in the audio SETUP.  The audio key comes from the
ekey/eiv rather than the id, and the RTP packets carry ssrc 0 to match
the reference sender, so the announcement appears nowhere else and cannot disagree with
anything.  That is why it is not pinned, and why pinning it would assert a
literal rather than a relationship.

WIRE-CONSTANT SWEEP, AND WHY MOST OF IT SURVIVES.  Every string constant
that reaches a receiver -- SETUP body values, headers, module-level protocol
names -- was replaced with a marker and the whole suite run.  Twenty-four
sites, ten killed.

The fourteen survivors are not fourteen gaps.  Three were dead: the
``MirrorVideo-*`` HKDF labels had no reader at all, because the video key
turned out to be FairPlay-derived rather than HAP-derived, and they have been
removed.  The rest were HKDF salt and info strings on a dialect that has
since been removed, whose exact values a receiver expects were unconfirmed.
Pinning a provisional value would have frozen a guess.

That is the honest reading of a survivor list on a protocol reimplementation:
some entries are missing tests, some are dead code, and some are work that is
not finished.  Only the first kind is worth a test.

THE REVERSE SWEEP: PORTS THE RECEIVER ANNOUNCES.  The same exercise run the
other way -- each port the Apple TV hands back was redirected by one and the
suite timed, not just watched.  Everything was already caught, but not
equally well:

* audio ``dataPort`` and the sync's ``controlPort`` -- caught in 0.3s.
* ``eventPort`` -- caught; TCP, so a wrong port is refused at connect.
* video ``dataPort`` -- caught; TCP again.  (A UDP video path, since
  removed, was caught only by every frame-waiting test hitting its guard
  timeout, which cost ten minutes and named nothing.)

The lesson is that "is it caught" and "how long does it take to say so" are
different questions, and only the second one distinguishes a usable failure
from a mysterious hang.  Time the bite-check.

One path stays unexercised: the sync's ``ctrl_udp`` fallback, used only when
no advertised control socket exists.  Mutating it changes nothing because
``adv_ctrl`` is always present in these tests.

A BITE-CHECK IS NOT A COVERAGE MEASUREMENT.  Showing that a mutation fails
a new test proves the test is sensitive to it.  It does not show the test
adds anything: the rest of the suite may already catch the same mutation.
Two tests here were justified that way and the justification was wrong --
of the four mutations the screen-audio test was written against, three were
already caught by ``test_screen_audio``'s unit tests, and the length-guard
raises in ``fairplay_sap`` were already being executed by their callers.
Both tests still earn their place, for narrower reasons than first claimed.

The measurement that answers the question is to run the mutation against the
suite with the new test *deselected*.  If it dies there, the new test is
redundant for that mutation.  It costs one extra run and it is the difference
between "this test is sensitive" and "this test is needed".

ON TEST DOUBLES THAT HIDE THE BUG.  A MagicMock that returns one fixed
value whatever it is asked for can make a mutant *equivalent*: a real HKDF
is argument-sensitive, and deriving from the wrong input under a fixed
double changes nothing observable.  When a mutation survives, check whether
a double flattened the thing it mutated before concluding the test is at
fault.

RUNNING THIS SUITE ON LINUX FROM A MAC.  CI covers ubuntu, macos and
windows; a developer on one of them covers one.  That gap once hid a real
bug -- a case calling Apple's CommonCrypto SPI would have failed on two of
the three -- so it is worth the ten minutes occasionally.
The recipe, which took several attempts:

* Install from ``requirements/requirements.txt`` and
  ``requirements_test.txt``, which is what CI does.  Hand-listing the
  packages instead gets the same answer here but is a recipe that can drift
  from CI, and a container that disagrees with CI is worse than no container
  -- it produces failures nobody else sees.
* Use ``python:3.12``, not ``-slim``.  ``import pyatv`` reaches ``miniaudio``
  through ``helpers.get_unique_id``, and that is a C extension with no wheel
  for every arch; slim has no compiler to build it.
* Copy ``examples/`` in too, excluding ``mirror_pyfply/devirt/out`` -- the
  sync test reads the devirt sources, and ``out/`` is 464MB of oracle.
  Without it, thirteen tests fail for a reason that is not about the code;
  that noise is easy to mistake for a platform problem.

RUN THIS SUITE IN A RANDOM ORDER OCCASIONALLY.  ``-p no:randomly`` is passed
almost everywhere here out of habit, and ``pytest-randomly`` is not a declared
dependency, so the flag is usually a no-op and the order never varies.
Installing it into a scratch environment and picking a few seeds found a real
hang on the first try: a live-path test waited for three TCP READS from a
source that sends three MESSAGES, and if two of them coalesced there was no
third read and the wait never returned.  A fixed order had hidden it for as
long as the coalescing happened to go the other way.

Since then: twenty seeds clean, every file clean run on its own, and all 62
tests in the two session files clean run one at a time.  The suite has no
module-level mutable shared between tests either -- the ``CAPTURED_*`` dicts
in ``fake_receiver`` are read-only expectations, never edited in place.  That
last one is worth keeping true; ``tests/test_conf.py`` outside this package
shows what the other way costs, where a module-level ``ManualService`` is
mutated by one test and read as pristine by another.

Note that installing ``pytest-randomly`` makes any unseeded run vary, which
includes a commit gate that runs pytest.  Fine in a scratch environment,
disruptive in the one used to decide whether a commit is good.

ON THE BROAD EXCEPT HANDLERS, WHICH ARE NOT A BLIND SPOT.  ``session.py``
has seven ``except Exception`` handlers that only log or pass, and a mutation
sweep cannot see past one: an error the handler swallows is an error no
assertion hears.  So they were tested the other way round -- by injecting a
fault inside each ``try`` rather than mutating it.

Faults in the event responder, the live video reader, the live audio
reader and the audio send loop are all noticed, because each of those
loops exists to produce something and the tests assert on what it
produced. A swallowed error stops the output, and stopping the output
fails a test.

Two cleanup mutations are invisible on their own -- the video producer's
``finally`` not killing its subprocess, and the audio sender's not killing
its own. That is redundancy rather than a gap: ``stop()`` kills both as
well, and removing BOTH kills is noticed at once. Worth knowing before
anyone deletes one of them as duplicated.

ON WAITING FOR THE WRONG THING.  Most tests here start a session, wait for
it to reach a steady state, then assert.  ``stream_then_stop`` does the
waiting and it waits on VIDEO, which is right for the many tests whose
assertion is that something did NOT happen -- a stale read can only make
those weaker, never wrong.  It is not right when the assertion is about
something else arriving.  Two tests written in this package waited on a
proxy for what they were about to assert, and both were wrong in a way
that passed:

* the live-audio test waited on video, which is ready almost at once, and
  stopped the session while the audio subprocess was still starting.  It
  saw no audio because none had been sent yet.
* the access-unit test waited on ``wait_frames(2)``.  That counter ticks
  once per TCP READ, not per protocol message, so two "frames" can be one
  message split in two or two messages coalesced into one.  It then asked
  for two whole messages and under load had one -- two runs in six of the
  full suite.

Both now wait on the condition they assert, counted by the same code that
does the asserting.  ``_messages()`` in ``test_session_error_paths`` drops
a trailing partial rather than guessing at it, which is what makes it
usable as a wait rather than only as a parser.  Eleven other tests share
the shape and were stressed rather than assumed innocent: 20 focused runs
and 8 full-suite runs, clean.  They assert absence, which is why.

AND ON THE HARNESS THAT REPORTS THE RESULT.  A mutation run answers with one
word, so the ways it can answer wrongly matter as much as the mutations.  Two
of them bit in one sitting, in opposite directions.  ``s.replace(old, new)``
that matches nothing raises nothing, so a mutation aimed at a string the file
does not contain -- a stale line number, a space that is not in the JSON --
came back SURVIVED, which reads as a hole in the tests and is really a hole
in the mutation.  And a ``timeout`` around pytest prints no "passed", so a
suite that ran over the cap came back CAUGHT: ``test_mba_synth`` takes 114
seconds against a 120-second cap.  One reported a gap that was not there and
the other reported coverage that was not there.

So the harness must refuse a snippet that leaves the file unchanged, and must
say TIMED OUT rather than let a timeout wear the same word as a failure.  A
survivor is only worth investigating once both of those are ruled out.

The third way is worse, because it outlives the run.  Restoring on an EXIT
trap covers a failure, a timeout and a Ctrl-C, and does not cover SIGKILL of
the process group -- which is exactly how a long campaign ends when whatever
launched it caps the time.  It has happened twice here, ``framing.py`` once
and ``session.py`` once, and both times the tree was left mutated and the
next test run read as a regression in the code.  A trap cannot fix this, so
the guard goes at the other end: refuse to mutate a file that already differs
from HEAD, since a leftover mutation and work in progress are indistinguish-
able from inside the harness.  If a mutation run reports failures that make
no sense, check ``git status`` before believing any of it.

AND ON WHAT A SIMPLIFYING PASS CAN SEE.  ``mba_cse`` matches repeated
subexpressions by their text, and that single fact has two consequences that
took a while to separate.

One sweep is not a fixed point.  Naming a fragment is exactly what makes its
other uses spell the same, so every hoist exposes repeats that were not
repeats before it -- ``garble`` settles only on the fifth sweep, at 4965
operators rather than 5072.  A pass whose input is its own output is worth
running to exhaustion rather than once.

And the pass was reading one statement too late.  It scanned for interfering
stores over the statements AFTER the first use, which misses the store that
first use itself performs: ``a = a * 3 + 7`` reads the old ``a`` and then
rebinds it, so every later ``a * 3 + 7`` is a different number, and hoisting
the first into the rest changed the answer with nothing to show for it.  The
hazard never arose in ``garble`` -- the port is byte-identical with the rule
fixed -- which is the uncomfortable part: 800 random buffers, 256 recorded
handshakes and a full equivalence check all passed either way, because they
can only see the port that was built, never the port that would have been
built from input one shape different.  The bug was found by asking what a
guard in a NEW branch was for and failing to write a test that reached it.
Coverage of the code that exists cannot report a rule that is wrong for
inputs the corpus does not contain; only reasoning about the rule can.
"""
