#ifndef ROD_H
#define ROD_H

// only use to prevent from editing the pkttable content

#include<QWidget>
#include<QItemDelegate>
#include<QStyleOptionViewItem>
class ReadOnlyDelegate: public QItemDelegate
{
public:
    ReadOnlyDelegate(QWidget *parent = NULL):QItemDelegate(parent)
    {}

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override //final
    {
        Q_UNUSED(parent)
        Q_UNUSED(option)
        Q_UNUSED(index)
        return NULL;
    }
};

#endif // ROD_H
