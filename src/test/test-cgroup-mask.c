/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "cgroup.h"
#include "cgroup-util.h"
#include "macro.h"
#include "manager.h"
#include "rm-rf.h"
#include "string-util.h"
#include "test-helper.h"
#include "tests.h"
#include "unit.h"

#define ASSERT_CGROUP_MASK(got, expected) \
        log_cgroup_mask(got, expected); \
        assert_se(got == expected)

#define ASSERT_CGROUP_MASK_JOINED(got, expected) ASSERT_CGROUP_MASK(got, CGROUP_MASK_EXTEND_JOINED(expected))

static void log_cgroup_mask(CGroupMask got, CGroupMask expected) {
        _cleanup_free_ char *e_store = NULL, *g_store = NULL;

        assert_se(cg_mask_to_string(expected, &e_store) >= 0);
        log_info("Expected mask: %s\n", e_store);
        assert_se(cg_mask_to_string(got, &g_store) >= 0);
        log_info("Got mask: %s\n", g_store);
}

static int test_cgroup_mask(void) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *son, *daughter, *parent, *root, *grandchild, *parent_deep, *nomem_parent, *nomem_leaf;
        int r;
        CGroupMask cpu_accounting_mask = get_cpu_accounting_mask();

        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        /* Prepare the manager. */
        assert_se(set_unit_path(get_testdata_dir()) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());
        r = manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (IN_SET(r, -EPERM, -EACCES)) {
                log_error_errno(r, "manager_new: %m");
                return log_tests_skipped("cannot create manager");
        }

        assert_se(r >= 0);

        /* Turn off all kinds of default accouning, so that we can
         * verify the masks resulting of our configuration and nothing
         * else. */
        m->default_cpu_accounting =
                m->default_memory_accounting =
                m->default_blockio_accounting =
                m->default_io_accounting =
                m->default_tasks_accounting = false;
        m->default_tasks_max = (uint64_t) -1;

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        /* Load units and verify hierarchy. */
        assert_se(manager_load_startable_unit_or_warn(m, "parent.slice", NULL, &parent) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "son.service", NULL, &son) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "daughter.service", NULL, &daughter) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "grandchild.service", NULL, &grandchild) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "parent-deep.slice", NULL, &parent_deep) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "nomem.slice", NULL, &nomem_parent) >= 0);
        assert_se(manager_load_startable_unit_or_warn(m, "nomemleaf.service", NULL, &nomem_leaf) >= 0);

        /* dml.slice has DefaultMemoryLow=50. Beyond that, individual subhierarchies look like this:
         *
         * 1. dml_passthrough.slice sets MemoryLow=100. This should not affect its children, as only
         *    DefaultMemoryLow is propagated, not MemoryLow. As such, all leaf services should end up with
         *    memory.low as 50, inherited from dml.slice, *except* for dml_passthrough_set_ml.service, which
         *    should have the value of 25, as it has MemoryLow explicitly set.
         *
         *                                                  ┌───────────┐
         *                                                  │ dml.slice │
         *                                                  └─────┬─────┘
         *                                                   MemoryLow=50
         *                                            ┌───────────┴───────────┐
         *                                            │ dml_passthrough.slice │
         *                                            └───────────┬───────────┘
         *                    ┌───────────────────────────────────┼───────────────────────────────────┐
         *             no new settings                   DefaultMemoryLow=15                     MemoryLow=25
         *    ┌───────────────┴───────────────┐  ┌────────────────┴────────────────┐  ┌───────────────┴────────────────┐
         *    │ dml_passthrough_empty.service │  │ dml_passthrough_set_dml.service │  │ dml_passthrough_set_ml.service │
         *    └───────────────────────────────┘  └─────────────────────────────────┘  └────────────────────────────────┘
         *
         * 2. dml_override.slice sets DefaultMemoryLow=10. As such, dml_override_empty.service should also
         *    end up with a memory.low of 10. dml_override.slice should still have a memory.low of 50.
         *
         *            ┌───────────┐
         *            │ dml.slice │
         *            └─────┬─────┘
         *         DefaultMemoryLow=10
         *        ┌─────────┴──────────┐
         *        │ dml_override.slice │
         *        └─────────┬──────────┘
         *           no new settings
         *    ┌─────────────┴──────────────┐
         *    │ dml_override_empty.service │
         *    └────────────────────────────┘
         *
         * 3. dml_discard.slice sets DefaultMemoryLow= with no rvalue. As such,
         *    dml_discard_empty.service should end up with a value of 0.
         *    dml_discard_explicit_ml.service sets MemoryLow=70, and as such should have that override the
         *    reset DefaultMemoryLow value. dml_discard.slice should still have an eventual memory.low of 50.
         *
         *                           ┌───────────┐
         *                           │ dml.slice │
         *                           └─────┬─────┘
         *                          no new settings
         *                       ┌─────────┴─────────┐
         *                       │ dml_discard.slice │
         *                       └─────────┬─────────┘
         *                  ┌──────────────┴───────────────┐
         *           no new settings                  MemoryLow=15
         *    ┌─────────────┴─────────────┐  ┌─────────────┴──────────────┐
         *    │ dml_discard_empty.service │  │ dml_discard_set_ml.service │
         *    └───────────────────────────┘  └────────────────────────────┘
         */
        assert_se(manager_load_startable_unit_or_warn(m, "dml.slice", NULL, &dml) >= 0);

        assert_se(manager_load_startable_unit_or_warn(m, "dml_passthrough.slice", NULL, &dml_passthrough) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml_passthrough_empty.service", NULL, &dml_passthrough_empty) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough_empty->slice) == dml_passthrough);
        assert_se(manager_load_startable_unit_or_warn(m, "dml_passthrough_set_dml.service", NULL, &dml_passthrough_set_dml) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough_set_dml->slice) == dml_passthrough);
        assert_se(manager_load_startable_unit_or_warn(m, "dml_passthrough_set_ml.service", NULL, &dml_passthrough_set_ml) >= 0);
        assert_se(UNIT_DEREF(dml_passthrough_set_ml->slice) == dml_passthrough);

        assert_se(manager_load_startable_unit_or_warn(m, "dml_override.slice", NULL, &dml_override) >= 0);
        assert_se(UNIT_DEREF(dml_override->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml_override_empty.service", NULL, &dml_override_empty) >= 0);
        assert_se(UNIT_DEREF(dml_override_empty->slice) == dml_override);

        assert_se(manager_load_startable_unit_or_warn(m, "dml_discard.slice", NULL, &dml_discard) >= 0);
        assert_se(UNIT_DEREF(dml_discard->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml_discard_empty.service", NULL, &dml_discard_empty) >= 0);
        assert_se(UNIT_DEREF(dml_discard_empty->slice) == dml);
        assert_se(manager_load_startable_unit_or_warn(m, "dml_discard_set_ml.service", NULL, &dml_discard_set_ml) >= 0);
        assert_se(UNIT_DEREF(dml_discard_set_ml->slice) == dml_discard);

        assert_se(UNIT_DEREF(son->slice) == parent);
        assert_se(UNIT_DEREF(daughter->slice) == parent);
        assert_se(UNIT_DEREF(parent_deep->slice) == parent);
        assert_se(UNIT_DEREF(grandchild->slice) == parent_deep);
        assert_se(UNIT_DEREF(nomem_leaf->slice) == nomem_parent);
        root = UNIT_DEREF(parent->slice);
        assert_se(UNIT_DEREF(nomem_parent->slice) == root);

        /* Verify per-unit cgroups settings. */
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(son), CGROUP_MASK_CPU);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(daughter), cpu_accounting_mask);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(grandchild), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(parent_deep), CGROUP_MASK_MEMORY);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(parent), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO));
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(nomem_parent), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(nomem_leaf), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO));
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(root), 0);

        /* Verify aggregation of member masks */
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(son), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(daughter), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(grandchild), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(parent_deep), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(parent), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(nomem_parent), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO));
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(nomem_leaf), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(root), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of sibling masks. */
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(son), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(daughter), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(grandchild), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(parent_deep), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(parent), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(nomem_parent), (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(nomem_leaf), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(root), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of target masks. */
        ASSERT_CGROUP_MASK(unit_get_target_mask(son), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(daughter), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_target_mask(parent_deep), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(parent), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(nomem_parent), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(nomem_leaf), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_IO | CGROUP_MASK_BLKIO) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(root), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));

        return 0;
}

static void test_cg_mask_to_string_one(CGroupMask mask, const char *t) {
        _cleanup_free_ char *b = NULL;

        assert_se(cg_mask_to_string(mask, &b) >= 0);
        assert_se(streq_ptr(b, t));
}

static void test_cg_mask_to_string(void) {
        test_cg_mask_to_string_one(0, NULL);
        test_cg_mask_to_string_one(_CGROUP_MASK_ALL, "cpu cpuacct io blkio memory devices pids bpf-firewall bpf-devices");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU, "cpu");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUACCT, "cpuacct");
        test_cg_mask_to_string_one(CGROUP_MASK_IO, "io");
        test_cg_mask_to_string_one(CGROUP_MASK_BLKIO, "blkio");
        test_cg_mask_to_string_one(CGROUP_MASK_MEMORY, "memory");
        test_cg_mask_to_string_one(CGROUP_MASK_DEVICES, "devices");
        test_cg_mask_to_string_one(CGROUP_MASK_PIDS, "pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU|CGROUP_MASK_CPUACCT, "cpu cpuacct");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU|CGROUP_MASK_PIDS, "cpu pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUACCT|CGROUP_MASK_PIDS, "cpuacct pids");
        test_cg_mask_to_string_one(CGROUP_MASK_DEVICES|CGROUP_MASK_PIDS, "devices pids");
        test_cg_mask_to_string_one(CGROUP_MASK_IO|CGROUP_MASK_BLKIO, "io blkio");
}

int main(int argc, char* argv[]) {
        int rc = EXIT_SUCCESS;

        test_setup_logging(LOG_DEBUG);

        test_cg_mask_to_string();
        TEST_REQ_RUNNING_SYSTEMD(rc = test_cgroup_mask());

        return rc;
}
