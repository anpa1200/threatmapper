import '@xyflow/react/dist/style.css';
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react';

export function EntityGraph({
  nodes,
  edges,
  fitView = true,
  compact = false,
}: {
  nodes: Node[];
  edges: Edge[];
  fitView?: boolean;
  compact?: boolean;
}) {
  return (
    <div className={`h-full overflow-hidden rounded border border-gray-800 bg-gray-950 ${compact ? 'min-h-0' : 'min-h-[360px]'}`}>
      <ReactFlow nodes={nodes} edges={edges} fitView={fitView} fitViewOptions={{ padding: compact ? 0.2 : 0.12 }} colorMode="dark">
        <Background color="#1f2937" gap={18} />
        <MiniMap
          pannable
          zoomable
          className={`!bg-gray-950 ${compact ? '!h-20 !w-28 !border !border-gray-800 !opacity-80' : ''}`}
        />
        <Controls className="!border-gray-800 !bg-gray-950 !text-gray-200" />
      </ReactFlow>
    </div>
  );
}
