/*
 * QEMU TDX support
 *
 * Copyright Intel
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qapi/qapi-visit-sockets.h"

#include "tdx-quote-generator.h"

typedef struct TdxQuoteGeneratorClass {
    DeviceClass parent_class;
} TdxQuoteGeneratorClass;

OBJECT_DEFINE_TYPE(TdxQuoteGenerator, tdx_quote_generator, TDX_QUOTE_GENERATOR, OBJECT)

static void tdx_quote_generator_finalize(Object *obj)
{
}

static void tdx_quote_generator_class_init(ObjectClass *oc, void *data)
{
}

static void tdx_quote_generator_init(Object *obj)
{
}

static void tdx_generate_quote_cleanup(struct tdx_generate_quote_task *task)
{
    timer_del(&task->timer);

    g_source_remove(task->watch);
    qio_channel_close(QIO_CHANNEL(task->sioc), NULL);
    object_unref(OBJECT(task->sioc));

    /* Maintain the number of in-flight requests. */
    qemu_mutex_lock(&task->quote_gen->lock);
    task->quote_gen->num--;
    qemu_mutex_unlock(&task->quote_gen->lock);

    task->completion(task);
}

static gboolean tdx_get_quote_read(QIOChannel *ioc, GIOCondition condition,
                                   gpointer opaque)
{
    struct tdx_generate_quote_task *task = opaque;
    Error *err = NULL;
    int ret;

    ret = qio_channel_read(ioc, task->receive_buf + task->receive_buf_received,
                           task->payload_len - task->receive_buf_received, &err);
    if (ret < 0) {
        if (ret ==  QIO_CHANNEL_ERR_BLOCK) {
            return G_SOURCE_CONTINUE;
        } else {
            error_report_err(err);
            task->status_code = TDX_VP_GET_QUOTE_ERROR;
            goto end;
        }
    }

    task->receive_buf_received += ret;
    if (ret == 0 || task->receive_buf_received == task->payload_len) {
        task->status_code = TDX_VP_GET_QUOTE_SUCCESS;
        goto end;
    }

    return G_SOURCE_CONTINUE;

end:
    tdx_generate_quote_cleanup(task);
    return G_SOURCE_REMOVE;
}

static gboolean tdx_send_report(QIOChannel *ioc, GIOCondition condition,
                                gpointer opaque)
{
    struct tdx_generate_quote_task *task = opaque;
    Error *err = NULL;
    int ret;

    ret = qio_channel_write(ioc, task->send_data + task->send_data_sent,
                            task->send_data_size - task->send_data_sent, &err);
    if (ret < 0) {
        if (ret == QIO_CHANNEL_ERR_BLOCK) {
            ret = 0;
        } else {
            error_report_err(err);
            task->status_code = TDX_VP_GET_QUOTE_ERROR;
            tdx_generate_quote_cleanup(task);
            goto end;
        }
    }
    task->send_data_sent += ret;

    if (task->send_data_sent == task->send_data_size) {
        task->watch = qio_channel_add_watch(QIO_CHANNEL(task->sioc), G_IO_IN,
                                            tdx_get_quote_read, task, NULL);
        goto end;
    }

    return G_SOURCE_CONTINUE;

end:
    return G_SOURCE_REMOVE;
}

static void tdx_quote_generator_connected(QIOTask *qio_task, gpointer opaque)
{
    struct tdx_generate_quote_task *task = opaque;
    Error *err = NULL;
    int ret;

    ret = qio_task_propagate_error(qio_task, &err);
    if (ret) {
        error_report_err(err);
        task->status_code = TDX_VP_GET_QUOTE_QGS_UNAVAILABLE;
        tdx_generate_quote_cleanup(task);
        return;
    }

    task->watch = qio_channel_add_watch(QIO_CHANNEL(task->sioc), G_IO_OUT,
                                        tdx_send_report, task, NULL);
}

#define TRANSACTION_TIMEOUT 30000

static void getquote_expired(void *opaque)
{
    struct tdx_generate_quote_task *task = opaque;

    task->status_code = TDX_VP_GET_QUOTE_ERROR;
    tdx_generate_quote_cleanup(task);
}

static void setup_get_quote_timer(struct tdx_generate_quote_task *task)
{
    int64_t time;

    timer_init_ms(&task->timer, QEMU_CLOCK_VIRTUAL, getquote_expired, task);
    time = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    timer_mod(&task->timer, time + TRANSACTION_TIMEOUT);
}

void tdx_generate_quote(struct tdx_generate_quote_task *task)
{
    struct TdxQuoteGenerator *quote_gen = task->quote_gen;
    QIOChannelSocket *sioc;

    sioc = qio_channel_socket_new();
    task->sioc = sioc;

    setup_get_quote_timer(task);

    qio_channel_socket_connect_async(sioc, quote_gen->socket,
                                     tdx_quote_generator_connected, task,
                                     NULL, NULL);
}
